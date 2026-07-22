use serde::{Serialize, Serializer};
use std::collections::BTreeMap;
use std::mem::size_of;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::analyzer::complete_value_cache::{
    CompleteValueAcquisition, CompleteValueCache, CompleteValueWait,
};
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::{IAnalyzer, Language, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::compact_graph::CompactDirectedGraph;
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;

/// The semantic family of one reusable, immutable query-execution layer.
///
/// A runtime layer owner must define its complete validity key next to its
/// materializer. See `CompleteValueCache` for the required key dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DerivedLayerKind {
    DirectImportTopology,
}

/// The plan-known shape of a reusable value requested by one physical query
/// operator.
///
/// This is deliberately not a bound cache key: physical selection has no
/// analyzer snapshot or runtime resolver configuration. The snapshot owner
/// rotates the backing complete-value cache when the live source generation
/// changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub(crate) struct DerivedLayerRequest {
    kind: DerivedLayerKind,
    #[serde(serialize_with = "serialize_stable_digest")]
    projection_filter_fingerprint: StableDigest,
    representation_version: u32,
}

impl DerivedLayerRequest {
    const DIRECT_IMPORT_TOPOLOGY_REPRESENTATION_VERSION: u32 = 1;
    const COMPLETE_DIRECT_IMPORT_TOPOLOGY_REQUEST: &[u8] =
        b"bifrost-derived-layer:direct-import-topology:complete:no-filter";

    /// Request the complete project-local direct import topology.
    ///
    /// Reverse import traversal needs this complete relation. Forward import
    /// traversal is frontier-dependent and therefore does not force a build,
    /// but may reuse a topology already acquired by another step or request.
    pub(crate) fn complete_direct_import_topology() -> Self {
        Self {
            kind: DerivedLayerKind::DirectImportTopology,
            projection_filter_fingerprint: StableDigest::sha256(
                Self::COMPLETE_DIRECT_IMPORT_TOPOLOGY_REQUEST,
            ),
            representation_version: Self::DIRECT_IMPORT_TOPOLOGY_REPRESENTATION_VERSION,
        }
    }
}

fn serialize_stable_digest<S>(digest: &StableDigest, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&digest.to_string())
}

/// One complete immutable derived representation retained by an analyzer
/// snapshot. Variants must retain enough support metadata to avoid turning an
/// unsupported or partial relation into exact-looking edges.
#[derive(Debug)]
pub(crate) enum DerivedLayer {
    DirectImportTopology(DirectImportTopology),
}

impl DerivedLayer {
    pub(crate) fn direct_import_topology(&self) -> &DirectImportTopology {
        match self {
            Self::DirectImportTopology(topology) => topology,
        }
    }

    fn retained_bytes(&self) -> u64 {
        match self {
            Self::DirectImportTopology(topology) => topology.retained_bytes(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DerivedLayerBuildMetrics {
    pub(crate) resolved_files: u64,
    pub(crate) resolved_edges: u64,
    pub(crate) elapsed_ns: u64,
    pub(crate) retained_bytes: u64,
}

pub(crate) enum DerivedLayerBuildOutcome {
    Complete {
        layer: DerivedLayer,
        metrics: DerivedLayerBuildMetrics,
    },
    Cancelled {
        metrics: DerivedLayerBuildMetrics,
    },
    Unavailable {
        reason: String,
        over_budget: bool,
        rejection_scope: Option<DerivedLayerRejectionScope>,
        metrics: DerivedLayerBuildMetrics,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DerivedLayerRejectionScope {
    RequestBudget,
    SnapshotBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DerivedLayerLifecycle {
    Hit,
    Built,
}

pub(crate) enum DerivedLayerAcquisition {
    Ready {
        layer: Arc<DerivedLayer>,
        lifecycle: DerivedLayerLifecycle,
        wait: CompleteValueWait,
        build: DerivedLayerBuildMetrics,
    },
    Cancelled {
        wait: CompleteValueWait,
        build: DerivedLayerBuildMetrics,
    },
    Unavailable {
        reason: String,
        over_budget: bool,
        rejection_scope: Option<DerivedLayerRejectionScope>,
        wait: CompleteValueWait,
        build: DerivedLayerBuildMetrics,
    },
}

struct DerivedLayerGeneration {
    source_generations: Box<[u64]>,
    values: Arc<CompleteValueCache<DerivedLayerRequest, DerivedLayer>>,
    auto_reuse_requests: HashSet<DerivedLayerRequest>,
    auto_rejections: HashMap<DerivedLayerRequest, Vec<(usize, usize)>>,
    snapshot_rejections: HashSet<DerivedLayerRequest>,
}

/// Snapshot-owned complete derived values with generation-safe single-flight.
///
/// The authored request stays representation-neutral. A mutable overlay can
/// advance its generation without replacing the analyzer object, so the owner
/// atomically rotates to a fresh backing cache and refuses a late stale build.
pub struct SnapshotDerivedLayerCache {
    max_retained_bytes: u64,
    generation: Mutex<Option<DerivedLayerGeneration>>,
}

impl SnapshotDerivedLayerCache {
    pub(crate) const DEFAULT_MAX_RETAINED_BYTES: u64 = 32 * 1024 * 1024;

    pub(crate) fn new(max_retained_bytes: u64) -> Self {
        Self {
            max_retained_bytes,
            generation: Mutex::new(None),
        }
    }

    fn new_values(&self) -> Arc<CompleteValueCache<DerivedLayerRequest, DerivedLayer>> {
        Arc::new(CompleteValueCache::new(
            self.max_retained_bytes,
            |_, layer: &Arc<DerivedLayer>| layer.retained_bytes().clamp(1, u32::MAX as u64) as u32,
        ))
    }

    fn with_generation<T>(
        &self,
        source_generations: &[u64],
        use_generation: impl FnOnce(&mut DerivedLayerGeneration) -> T,
    ) -> Option<T> {
        let mut generation = self
            .generation
            .lock()
            .expect("snapshot derived-layer generation mutex poisoned");
        match generation.as_ref() {
            Some(current) if current.source_generations.as_ref() > source_generations => {
                return None;
            }
            Some(current) if current.source_generations.as_ref() == source_generations => {}
            Some(_) | None => {
                *generation = Some(DerivedLayerGeneration {
                    source_generations: source_generations.into(),
                    values: self.new_values(),
                    auto_reuse_requests: HashSet::default(),
                    auto_rejections: HashMap::default(),
                    snapshot_rejections: HashSet::default(),
                });
            }
        }
        Some(use_generation(
            generation
                .as_mut()
                .expect("derived-layer generation was initialized"),
        ))
    }

    fn values_for(
        &self,
        source_generations: &[u64],
    ) -> Option<Arc<CompleteValueCache<DerivedLayerRequest, DerivedLayer>>> {
        self.with_generation(source_generations, |generation| {
            Arc::clone(&generation.values)
        })
    }

    pub(crate) fn get_ready(
        &self,
        request: DerivedLayerRequest,
        source_generations: &[u64],
        cancellation: &CancellationToken,
    ) -> Option<Arc<DerivedLayer>> {
        self.values_for(source_generations)
            .and_then(|values| values.get_ready(&request, cancellation))
    }

    pub(crate) fn max_retained_bytes(&self) -> u64 {
        self.max_retained_bytes
    }

    /// Auto avoids constructing a whole-workspace relation for a one-off
    /// query. The first viable request records reuse interest and falls back;
    /// a later request for the same snapshot and representation may build.
    pub(crate) fn observe_auto_reuse_opportunity(
        &self,
        request: DerivedLayerRequest,
        source_generations: &[u64],
        max_files: usize,
        max_edges: usize,
    ) -> bool {
        self.with_generation(source_generations, |generation| {
            if generation.snapshot_rejections.contains(&request)
                || generation
                    .auto_rejections
                    .get(&request)
                    .is_some_and(|rejections| {
                        rejections.iter().any(|(rejected_files, rejected_edges)| {
                            max_files <= *rejected_files && max_edges <= *rejected_edges
                        })
                    })
            {
                return false;
            }
            !generation.auto_reuse_requests.insert(request)
        })
        .unwrap_or(false)
    }

    pub(crate) fn record_auto_rejection(
        &self,
        request: DerivedLayerRequest,
        source_generations: &[u64],
        max_files: usize,
        max_edges: usize,
        scope: DerivedLayerRejectionScope,
    ) {
        let _ = self.with_generation(source_generations, |generation| {
            if scope == DerivedLayerRejectionScope::SnapshotBudget {
                generation.snapshot_rejections.insert(request);
                generation.auto_rejections.remove(&request);
                return;
            }
            let rejections = generation.auto_rejections.entry(request).or_default();
            if rejections
                .iter()
                .any(|(files, edges)| max_files <= *files && max_edges <= *edges)
            {
                return;
            }
            rejections.retain(|(files, edges)| *files > max_files || *edges > max_edges);
            rejections.push((max_files, max_edges));
        });
    }

    pub(crate) fn acquire(
        &self,
        request: DerivedLayerRequest,
        source_generations: &[u64],
        cancellation: &CancellationToken,
        build: impl FnOnce() -> DerivedLayerBuildOutcome,
        generation_is_current: impl Fn() -> bool,
    ) -> DerivedLayerAcquisition {
        let Some(values) = self.values_for(source_generations) else {
            return DerivedLayerAcquisition::Unavailable {
                reason: "derived-layer source generation is older than the cache owner".to_string(),
                over_budget: false,
                rejection_scope: None,
                wait: CompleteValueWait::default(),
                build: DerivedLayerBuildMetrics::default(),
            };
        };
        let (acquisition, wait) = values.acquire(&request, cancellation);
        match acquisition {
            CompleteValueAcquisition::Cached { value } => {
                if !generation_is_current() {
                    return DerivedLayerAcquisition::Unavailable {
                        reason: "derived-layer source generation changed before reuse".to_string(),
                        over_budget: false,
                        rejection_scope: None,
                        wait,
                        build: DerivedLayerBuildMetrics::default(),
                    };
                }
                DerivedLayerAcquisition::Ready {
                    layer: value,
                    lifecycle: DerivedLayerLifecycle::Hit,
                    wait,
                    build: DerivedLayerBuildMetrics::default(),
                }
            }
            CompleteValueAcquisition::Leader { permit } => match build() {
                DerivedLayerBuildOutcome::Complete { layer, mut metrics } => {
                    metrics.retained_bytes = layer.retained_bytes();
                    if cancellation.is_cancelled() {
                        return DerivedLayerAcquisition::Cancelled {
                            wait,
                            build: metrics,
                        };
                    }
                    if !generation_is_current() {
                        permit.publish_rejected();
                        return DerivedLayerAcquisition::Unavailable {
                            reason: "derived-layer source generation changed during build"
                                .to_string(),
                            over_budget: false,
                            rejection_scope: None,
                            wait,
                            build: metrics,
                        };
                    }
                    if metrics.retained_bytes > self.max_retained_bytes {
                        permit.publish_rejected();
                        return DerivedLayerAcquisition::Unavailable {
                            reason: format!(
                                "derived layer retained-byte limit exceeded: {} > {}",
                                metrics.retained_bytes, self.max_retained_bytes
                            ),
                            over_budget: true,
                            rejection_scope: Some(DerivedLayerRejectionScope::SnapshotBudget),
                            wait,
                            build: metrics,
                        };
                    }
                    let layer = Arc::new(layer);
                    permit.publish_complete(Arc::clone(&layer));
                    if !generation_is_current() {
                        return DerivedLayerAcquisition::Unavailable {
                            reason: "derived-layer source generation changed during publication"
                                .to_string(),
                            over_budget: false,
                            rejection_scope: None,
                            wait,
                            build: metrics,
                        };
                    }
                    DerivedLayerAcquisition::Ready {
                        layer,
                        lifecycle: DerivedLayerLifecycle::Built,
                        wait,
                        build: metrics,
                    }
                }
                DerivedLayerBuildOutcome::Cancelled { metrics } => {
                    DerivedLayerAcquisition::Cancelled {
                        wait,
                        build: metrics,
                    }
                }
                DerivedLayerBuildOutcome::Unavailable {
                    reason,
                    over_budget,
                    rejection_scope,
                    metrics,
                } => {
                    let generation_is_current = generation_is_current();
                    if rejection_scope.is_some() {
                        permit.publish_rejected();
                    }
                    if !generation_is_current {
                        DerivedLayerAcquisition::Unavailable {
                            reason: "derived-layer source generation changed during failed build"
                                .to_string(),
                            over_budget: false,
                            rejection_scope: None,
                            wait,
                            build: metrics,
                        }
                    } else {
                        DerivedLayerAcquisition::Unavailable {
                            reason,
                            over_budget,
                            rejection_scope,
                            wait,
                            build: metrics,
                        }
                    }
                }
            },
            CompleteValueAcquisition::Rejected => DerivedLayerAcquisition::Unavailable {
                reason: "derived-layer construction rejected by same-key leader".to_string(),
                over_budget: false,
                rejection_scope: None,
                wait,
                build: DerivedLayerBuildMetrics::default(),
            },
            CompleteValueAcquisition::Cancelled => DerivedLayerAcquisition::Cancelled {
                wait,
                build: DerivedLayerBuildMetrics::default(),
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn len_for_test(&self, source_generations: &[u64]) -> u64 {
        self.values_for(source_generations)
            .map_or(0, |values| values.len_for_test())
    }

    #[cfg(test)]
    fn waiting_count_for_test(&self, source_generations: &[u64]) -> usize {
        self.values_for(source_generations)
            .map_or(0, |values| values.waiting_count_for_test())
    }
}

impl Default for SnapshotDerivedLayerCache {
    fn default() -> Self {
        Self::new(Self::DEFAULT_MAX_RETAINED_BYTES)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DirectImportTopologyLimits {
    pub(crate) max_files: usize,
    pub(crate) max_edges: usize,
    pub(crate) max_retained_bytes: u64,
}

pub(crate) struct DirectImportTopologyBuild {
    pub(crate) outcome: DerivedLayerBuildOutcome,
    pub(crate) fallback: Option<RequestLocalDirectImportGraph>,
}

/// Complete import resolution for every analyzed file in one declared support
/// domain. Unsupported files are retained as dense support bits; the reverse
/// relation is exact only when all possible source files were supported.
#[derive(Debug)]
pub(crate) struct DirectImportTopology {
    graph: CompactDirectedGraph<ProjectFile>,
    supported_sources: Box<[bool]>,
    resolved_files: usize,
    retained_bytes: u64,
}

impl DirectImportTopology {
    pub(crate) fn imports_of(&self, file: &ProjectFile) -> Option<Vec<ProjectFile>> {
        let source = self.graph.node_id(file)?;
        if !self.supported_sources[source as usize] {
            return None;
        }
        Some(
            self.graph
                .outgoing(source)
                .iter()
                .map(|target| self.graph.nodes()[*target as usize].clone())
                .collect(),
        )
    }

    #[cfg(test)]
    fn importers_of(&self, file: &ProjectFile) -> Option<Vec<ProjectFile>> {
        if !self.reverse_relation_complete() {
            return None;
        }
        Some(self.known_importers_of(file))
    }

    pub(crate) fn known_importers_of(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        let Some(target) = self.graph.node_id(file) else {
            return Vec::new();
        };
        self.graph
            .incoming(target)
            .iter()
            .map(|source| self.graph.nodes()[*source as usize].clone())
            .collect()
    }

    pub(crate) fn import_count(&self, file: &ProjectFile) -> Option<usize> {
        let source = self.graph.node_id(file)?;
        self.supported_sources[source as usize].then(|| self.graph.outgoing(source).len())
    }

    pub(crate) fn known_importer_count(&self, file: &ProjectFile) -> usize {
        self.graph
            .node_id(file)
            .map_or(0, |target| self.graph.incoming(target).len())
    }

    pub(crate) fn reverse_relation_complete(&self) -> bool {
        self.supported_sources.iter().all(|supported| *supported)
    }

    pub(crate) fn unsupported_languages(&self) -> Vec<Language> {
        let mut languages = self
            .graph
            .nodes()
            .iter()
            .zip(&self.supported_sources)
            .filter(|(_, supported)| !**supported)
            .map(|(file, _)| crate::analyzer::common::language_for_file(file))
            .collect::<Vec<_>>();
        languages.sort();
        languages.dedup();
        languages
    }

    pub(crate) fn resolved_files(&self) -> usize {
        self.resolved_files
    }

    pub(crate) fn resolved_edges(&self) -> usize {
        self.graph.edge_count()
    }

    pub(crate) fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }
}

pub(crate) fn build_direct_import_topology(
    analyzer: &dyn IAnalyzer,
    cancellation: &CancellationToken,
    limits: DirectImportTopologyLimits,
) -> DirectImportTopologyBuild {
    let started = Instant::now();
    let mut metrics = DerivedLayerBuildMetrics::default();
    let mut files = analyzer.analyzed_files();
    canonicalize_project_files(&mut files);
    if files.len() > limits.max_files || u32::try_from(files.len()).is_err() {
        metrics.elapsed_ns = elapsed_ns(started);
        return DirectImportTopologyBuild {
            outcome: DerivedLayerBuildOutcome::Unavailable {
                reason: format!(
                    "direct import topology file limit exceeded: {} > {}",
                    files.len(),
                    limits.max_files
                ),
                over_budget: true,
                rejection_scope: Some(DerivedLayerRejectionScope::RequestBudget),
                metrics,
            },
            fallback: None,
        };
    }
    if cancellation.is_cancelled() {
        metrics.elapsed_ns = elapsed_ns(started);
        return DirectImportTopologyBuild {
            outcome: DerivedLayerBuildOutcome::Cancelled { metrics },
            fallback: None,
        };
    }

    let maximum_working_bytes = limits.max_retained_bytes.saturating_mul(3);
    if RequestLocalDirectImportGraph::fixed_working_bytes(&files) > maximum_working_bytes {
        metrics.elapsed_ns = elapsed_ns(started);
        return DirectImportTopologyBuild {
            outcome: DerivedLayerBuildOutcome::Unavailable {
                reason: "direct import topology construction-byte limit exceeded".to_string(),
                over_budget: true,
                rejection_scope: Some(DerivedLayerRejectionScope::SnapshotBudget),
                metrics,
            },
            fallback: None,
        };
    }

    let mut request_graph = RequestLocalDirectImportGraph::from_files(files);
    let (exhausted, construction_over_budget) = request_graph.resolve_complete_for_snapshot(
        analyzer,
        limits.max_files,
        limits.max_edges,
        cancellation,
        maximum_working_bytes,
    );
    metrics.resolved_files = u64::try_from(request_graph.resolved_files()).unwrap_or(u64::MAX);
    metrics.resolved_edges = u64::try_from(request_graph.resolved_edges()).unwrap_or(u64::MAX);
    if cancellation.is_cancelled() {
        metrics.elapsed_ns = elapsed_ns(started);
        return DirectImportTopologyBuild {
            outcome: DerivedLayerBuildOutcome::Cancelled { metrics },
            fallback: None,
        };
    }
    if exhausted {
        metrics.elapsed_ns = elapsed_ns(started);
        return DirectImportTopologyBuild {
            outcome: DerivedLayerBuildOutcome::Unavailable {
                reason: if construction_over_budget {
                    "direct import topology construction-byte limit exceeded".to_string()
                } else {
                    format!(
                        "direct import topology edge limit exceeded: more than {}",
                        limits.max_edges
                    )
                },
                over_budget: true,
                rejection_scope: Some(if construction_over_budget {
                    DerivedLayerRejectionScope::SnapshotBudget
                } else {
                    DerivedLayerRejectionScope::RequestBudget
                }),
                metrics,
            },
            fallback: Some(request_graph),
        };
    }

    let retained_bytes = request_graph.estimated_topology_retained_bytes();
    let projected_working_bytes = request_graph
        .estimated_working_bytes()
        .saturating_add(retained_bytes);
    if retained_bytes > limits.max_retained_bytes || projected_working_bytes > maximum_working_bytes
    {
        metrics.elapsed_ns = elapsed_ns(started);
        metrics.retained_bytes = retained_bytes;
        return DirectImportTopologyBuild {
            outcome: DerivedLayerBuildOutcome::Unavailable {
                reason: format!(
                    "direct import topology retained-byte limit exceeded: {retained_bytes} > {}",
                    limits.max_retained_bytes
                ),
                over_budget: true,
                rejection_scope: Some(DerivedLayerRejectionScope::SnapshotBudget),
                metrics,
            },
            fallback: Some(request_graph),
        };
    }

    request_graph.freeze();
    let retained_bytes = request_graph
        .compact
        .as_ref()
        .map(|graph| {
            (size_of::<DirectImportTopology>()
                .saturating_sub(size_of::<CompactDirectedGraph<ProjectFile>>()) as u64)
                .saturating_add(graph.estimated_bytes())
                .saturating_add(request_graph.all_files.len() as u64)
        })
        .expect("complete import graph was frozen");
    metrics.elapsed_ns = elapsed_ns(started);
    metrics.retained_bytes = retained_bytes;
    if retained_bytes > limits.max_retained_bytes {
        return DirectImportTopologyBuild {
            outcome: DerivedLayerBuildOutcome::Unavailable {
                reason: format!(
                    "direct import topology retained-byte limit exceeded: {retained_bytes} > {}",
                    limits.max_retained_bytes
                ),
                over_budget: true,
                rejection_scope: Some(DerivedLayerRejectionScope::SnapshotBudget),
                metrics,
            },
            fallback: Some(request_graph),
        };
    }
    let topology = request_graph.into_topology(retained_bytes);
    DirectImportTopologyBuild {
        outcome: DerivedLayerBuildOutcome::Complete {
            layer: DerivedLayer::DirectImportTopology(topology),
            metrics,
        },
        fallback: None,
    }
}

/// Request-local compatibility implementation used when snapshot acquisition
/// is disabled, incomplete, unsupported, cancelled, or over budget.
#[derive(Debug, Default)]
pub(crate) struct RequestLocalDirectImportGraph {
    forward: HashMap<ProjectFile, Vec<ProjectFile>>,
    compact: Option<CompactDirectedGraph<ProjectFile>>,
    unsupported: HashSet<ProjectFile>,
    budget_omitted: HashSet<ProjectFile>,
    all_files: Vec<ProjectFile>,
    analyzed: HashSet<ProjectFile>,
    attempted_files: usize,
    attempted_edges: usize,
    retained_edges: usize,
    forward_target_capacity: usize,
    complete: bool,
}

#[derive(Clone, Copy)]
struct RequestImportResolutionLimits<'a> {
    max_files: usize,
    max_edges: usize,
    cancellation: Option<&'a CancellationToken>,
    maximum_working_bytes: Option<u64>,
    files_are_canonical: bool,
}

impl RequestLocalDirectImportGraph {
    pub(crate) fn new(analyzer: &dyn IAnalyzer) -> Self {
        let mut all_files = analyzer.analyzed_files();
        canonicalize_project_files(&mut all_files);
        Self::from_files(all_files)
    }

    fn from_files(all_files: Vec<ProjectFile>) -> Self {
        let analyzed = all_files.iter().cloned().collect();
        Self {
            all_files,
            analyzed,
            ..Self::default()
        }
    }

    fn fixed_working_bytes(files: &[ProjectFile]) -> u64 {
        (size_of::<Self>() as u64).saturating_add((files.len() as u64).saturating_mul(
            (size_of::<ProjectFile>() * 5 + size_of::<(ProjectFile, Vec<ProjectFile>)>() * 2 + 5)
                as u64,
        ))
    }

    fn estimated_working_bytes(&self) -> u64 {
        (size_of::<Self>() as u64)
            .saturating_add(
                (self.all_files.capacity() as u64).saturating_mul(size_of::<ProjectFile>() as u64),
            )
            .saturating_add(
                (self.analyzed.capacity() as u64)
                    .saturating_mul((size_of::<ProjectFile>() + 1) as u64),
            )
            .saturating_add(
                (self.forward.capacity() as u64)
                    .saturating_mul((size_of::<(ProjectFile, Vec<ProjectFile>)>() + 1) as u64),
            )
            .saturating_add(
                (self.unsupported.capacity() as u64)
                    .saturating_mul((size_of::<ProjectFile>() + 1) as u64),
            )
            .saturating_add(
                (self.budget_omitted.capacity() as u64)
                    .saturating_mul((size_of::<ProjectFile>() + 1) as u64),
            )
            .saturating_add(
                (self.forward_target_capacity as u64)
                    .saturating_mul(size_of::<ProjectFile>() as u64),
            )
            .saturating_add(
                self.compact
                    .as_ref()
                    .map_or(0, CompactDirectedGraph::estimated_bytes),
            )
    }

    fn estimated_topology_retained_bytes(&self) -> u64 {
        (size_of::<DirectImportTopology>()
            .saturating_sub(size_of::<CompactDirectedGraph<ProjectFile>>()) as u64)
            .saturating_add(
                CompactDirectedGraph::<ProjectFile>::estimated_bytes_for_parts(
                    self.all_files.len(),
                    self.analyzed.capacity(),
                    self.retained_edges,
                ),
            )
            .saturating_add(self.all_files.len() as u64)
    }

    fn into_topology(mut self, retained_bytes: u64) -> DirectImportTopology {
        let graph = self
            .compact
            .take()
            .expect("complete request-local import graph must be frozen");
        let supported_sources = graph
            .nodes()
            .iter()
            .map(|file| !self.unsupported.contains(file))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        DirectImportTopology {
            graph,
            supported_sources,
            resolved_files: self.attempted_files,
            retained_bytes,
        }
    }

    fn freeze(&mut self) {
        if self.compact.is_some() {
            return;
        }
        let nodes = self.all_files.clone();
        let index_by_file: HashMap<_, _> = nodes
            .iter()
            .enumerate()
            .map(|(index, file)| (file.clone(), index as u32))
            .collect();
        let mut edges = Vec::with_capacity(self.retained_edges);
        for (source, targets) in &self.forward {
            let Some(source) = index_by_file.get(source).copied() else {
                continue;
            };
            edges.extend(targets.iter().filter_map(|target| {
                index_by_file
                    .get(target)
                    .copied()
                    .map(|target| (source, target))
            }));
        }
        self.compact = Some(CompactDirectedGraph::from_indexed_nodes(
            nodes,
            index_by_file,
            edges,
        ));
    }

    pub(crate) fn imports_of(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        if let Some(compact) = &self.compact {
            return compact
                .node_id(file)
                .into_iter()
                .flat_map(|source| compact.outgoing(source))
                .map(|target| compact.nodes()[*target as usize].clone())
                .collect();
        }
        self.forward.get(file).cloned().unwrap_or_default()
    }

    pub(crate) fn supports_source(&self, file: &ProjectFile) -> bool {
        !self.unsupported.contains(file)
    }

    pub(crate) fn importers_of(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        let Some(compact) = &self.compact else {
            return Vec::new();
        };
        compact
            .node_id(file)
            .into_iter()
            .flat_map(|target| compact.incoming(target))
            .map(|source| compact.nodes()[*source as usize].clone())
            .collect()
    }

    pub(crate) fn importer_count(&self, file: &ProjectFile) -> usize {
        let Some(compact) = &self.compact else {
            return 0;
        };
        compact
            .node_id(file)
            .map_or(0, |target| compact.incoming(target).len())
    }

    pub(crate) fn forward_relation_complete(&self, files: &[ProjectFile]) -> bool {
        files.iter().all(|file| self.forward.contains_key(file))
    }

    pub(crate) fn has_cached_forward(&self, file: &ProjectFile) -> bool {
        self.forward.contains_key(file)
            || self.unsupported.contains(file)
            || self.budget_omitted.contains(file)
    }

    pub(crate) fn cached_forward_edge_count(&self, file: &ProjectFile) -> usize {
        self.forward.get(file).map_or(0, Vec::len)
    }

    pub(crate) fn reverse_relation_complete(&self) -> bool {
        self.complete && self.unsupported.is_empty()
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.complete
    }

    pub(crate) fn unsupported_languages(&self) -> Vec<Language> {
        let mut languages = self
            .unsupported
            .iter()
            .map(crate::analyzer::common::language_for_file)
            .collect::<Vec<_>>();
        languages.sort();
        languages.dedup();
        languages
    }

    pub(crate) fn resolved_files(&self) -> usize {
        self.attempted_files
    }

    pub(crate) fn resolved_edges(&self) -> usize {
        self.attempted_edges
    }

    pub(crate) fn ensure_complete(
        &mut self,
        analyzer: &dyn IAnalyzer,
        max_files: usize,
        max_edges: usize,
        cancellation: Option<&CancellationToken>,
    ) -> bool {
        if self.complete {
            self.freeze();
            return false;
        }
        let files = self.all_files.clone();
        let (exhausted, _) = self.ensure_forward_inner(
            analyzer,
            &files,
            RequestImportResolutionLimits {
                max_files,
                max_edges,
                cancellation,
                maximum_working_bytes: None,
                files_are_canonical: true,
            },
        );
        if !exhausted {
            self.complete = true;
        }
        self.freeze();
        exhausted
    }

    fn resolve_complete_for_snapshot(
        &mut self,
        analyzer: &dyn IAnalyzer,
        max_files: usize,
        max_edges: usize,
        cancellation: &CancellationToken,
        maximum_working_bytes: u64,
    ) -> (bool, bool) {
        if self.complete {
            return (false, false);
        }
        let files = self.all_files.clone();
        let outcome = self.ensure_forward_inner(
            analyzer,
            &files,
            RequestImportResolutionLimits {
                max_files,
                max_edges,
                cancellation: Some(cancellation),
                maximum_working_bytes: Some(maximum_working_bytes),
                files_are_canonical: true,
            },
        );
        if !outcome.0 {
            self.complete = true;
        }
        outcome
    }

    pub(crate) fn ensure_forward(
        &mut self,
        analyzer: &dyn IAnalyzer,
        files: &[ProjectFile],
        max_files: usize,
        max_edges: usize,
        cancellation: Option<&CancellationToken>,
    ) -> bool {
        self.ensure_forward_inner(
            analyzer,
            files,
            RequestImportResolutionLimits {
                max_files,
                max_edges,
                cancellation,
                maximum_working_bytes: None,
                files_are_canonical: false,
            },
        )
        .0
    }

    fn ensure_forward_inner(
        &mut self,
        analyzer: &dyn IAnalyzer,
        files: &[ProjectFile],
        limits: RequestImportResolutionLimits<'_>,
    ) -> (bool, bool) {
        let RequestImportResolutionLimits {
            max_files,
            max_edges,
            cancellation,
            maximum_working_bytes,
            files_are_canonical,
        } = limits;
        let previously_omitted = files.iter().any(|file| self.budget_omitted.contains(file));
        let mut pending = files
            .iter()
            .filter(|file| {
                !self.forward.contains_key(*file)
                    && !self.unsupported.contains(*file)
                    && !self.budget_omitted.contains(*file)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !files_are_canonical {
            canonicalize_project_files(&mut pending);
        }
        if pending.is_empty() {
            return (previously_omitted, false);
        }

        let available_files = max_files.saturating_sub(self.attempted_files);
        let mut exhausted = previously_omitted || pending.len() > available_files;
        if pending.len() > available_files {
            pending.truncate(available_files);
        }

        let mut groups: BTreeMap<Language, Vec<ProjectFile>> = BTreeMap::new();
        for file in pending {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return (true, false);
            }
            if analyzer.import_analysis_provider_for_file(&file).is_some() {
                groups
                    .entry(crate::analyzer::common::language_for_file(&file))
                    .or_default()
                    .push(file);
            } else {
                self.attempted_files = self.attempted_files.saturating_add(1);
                self.unsupported.insert(file);
                self.compact = None;
                if maximum_working_bytes
                    .is_some_and(|maximum| self.estimated_working_bytes() > maximum)
                {
                    return (true, true);
                }
            }
        }

        for grouped_files in groups.values_mut() {
            let Some(provider) = grouped_files
                .first()
                .and_then(|file| analyzer.import_analysis_provider_for_file(file))
            else {
                continue;
            };
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return (true, false);
            }
            if self.attempted_edges >= max_edges {
                exhausted = true;
                self.budget_omitted.extend(grouped_files.iter().cloned());
                self.compact = None;
                continue;
            }
            let bulk_infos = provider.import_infos_for_files(grouped_files);
            // The provider has now materialized import information for the
            // whole canonical batch. Charge that real work even if a later
            // edge-budget check prevents retaining some resolved relations.
            self.attempted_files = self.attempted_files.saturating_add(grouped_files.len());
            for file in grouped_files.iter() {
                if cancellation.is_some_and(CancellationToken::is_cancelled) {
                    return (true, false);
                }
                if self.attempted_edges >= max_edges {
                    exhausted = true;
                    self.budget_omitted.insert(file.clone());
                    self.compact = None;
                    continue;
                }
                let owned_imports;
                let imports =
                    if let Some(imports) = bulk_infos.as_ref().and_then(|infos| infos.get(file)) {
                        imports.as_slice()
                    } else {
                        owned_imports = provider.import_info_of(file);
                        &owned_imports
                    };
                let mut targets =
                    crate::analyzer::resolve_imported_files_from_infos(provider, file, imports)
                        .into_iter()
                        .filter(|target| self.analyzed.contains(target))
                        .collect::<Vec<_>>();
                canonicalize_project_files(&mut targets);

                let transient_target_bytes = (targets.capacity() as u64)
                    .saturating_mul(size_of::<ProjectFile>() as u64)
                    .saturating_mul(2);
                self.attempted_edges = self.attempted_edges.saturating_add(targets.len());
                if maximum_working_bytes.is_some_and(|maximum| {
                    self.estimated_working_bytes()
                        .saturating_add(transient_target_bytes)
                        > maximum
                }) {
                    self.budget_omitted.insert(file.clone());
                    self.compact = None;
                    return (true, true);
                }

                let available_edges =
                    max_edges.saturating_sub(self.attempted_edges.saturating_sub(targets.len()));
                if targets.len() > available_edges {
                    exhausted = true;
                    self.budget_omitted.insert(file.clone());
                    self.compact = None;
                    continue;
                }
                self.retained_edges = self.retained_edges.saturating_add(targets.len());
                self.forward_target_capacity = self
                    .forward_target_capacity
                    .saturating_add(targets.capacity());
                self.forward.insert(file.clone(), targets);
                self.compact = None;
                if maximum_working_bytes
                    .is_some_and(|maximum| self.estimated_working_bytes() > maximum)
                {
                    return (true, true);
                }
            }
        }
        (exhausted, false)
    }
}

fn canonicalize_project_files(files: &mut Vec<ProjectFile>) {
    let mut keyed = files
        .drain(..)
        .map(|file| (rel_path_string(&file), file))
        .collect::<Vec<_>>();
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    keyed.dedup_by(|left, right| left.1 == right.1);
    files.extend(keyed.into_iter().map(|(_, file)| file));
}

fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{JavaAnalyzer, PhpAnalyzer, RubyAnalyzer, TestProject};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    fn complete_layer(retained_bytes: u64) -> DerivedLayerBuildOutcome {
        let file = ProjectFile::new(std::env::temp_dir(), "bifrost-derived-layer-test.ts");
        let graph = CompactDirectedGraph::new(vec![file], Vec::new());
        DerivedLayerBuildOutcome::Complete {
            layer: DerivedLayer::DirectImportTopology(DirectImportTopology {
                graph,
                supported_sources: vec![true].into_boxed_slice(),
                resolved_files: 1,
                retained_bytes,
            }),
            metrics: DerivedLayerBuildMetrics {
                resolved_files: 1,
                retained_bytes,
                ..DerivedLayerBuildMetrics::default()
            },
        }
    }

    #[test]
    fn snapshot_cache_reuses_and_rotates_by_source_generation() {
        let cache = SnapshotDerivedLayerCache::new(1024 * 1024);
        let request = DerivedLayerRequest::complete_direct_import_topology();
        let cancellation = CancellationToken::default();
        let builds = AtomicUsize::new(0);

        let first = cache.acquire(
            request,
            &[1],
            &cancellation,
            || {
                builds.fetch_add(1, Ordering::Relaxed);
                complete_layer(128)
            },
            || true,
        );
        assert!(matches!(
            first,
            DerivedLayerAcquisition::Ready {
                lifecycle: DerivedLayerLifecycle::Built,
                ..
            }
        ));
        let second = cache.acquire(
            request,
            &[1],
            &cancellation,
            || {
                builds.fetch_add(1, Ordering::Relaxed);
                complete_layer(128)
            },
            || true,
        );
        assert!(matches!(
            second,
            DerivedLayerAcquisition::Ready {
                lifecycle: DerivedLayerLifecycle::Hit,
                ..
            }
        ));
        let changed = cache.acquire(
            request,
            &[2],
            &cancellation,
            || {
                builds.fetch_add(1, Ordering::Relaxed);
                complete_layer(128)
            },
            || true,
        );
        assert!(matches!(
            changed,
            DerivedLayerAcquisition::Ready {
                lifecycle: DerivedLayerLifecycle::Built,
                ..
            }
        ));
        assert_eq!(builds.load(Ordering::Relaxed), 2);
        assert_eq!(cache.len_for_test(&[2]), 1);
    }

    #[test]
    fn delayed_older_generation_cannot_replace_the_current_cache() {
        let cache = SnapshotDerivedLayerCache::new(1024 * 1024);
        let request = DerivedLayerRequest::complete_direct_import_topology();
        let cancellation = CancellationToken::default();
        let builds = AtomicUsize::new(0);

        let current = cache.acquire(
            request,
            &[2],
            &cancellation,
            || {
                builds.fetch_add(1, Ordering::Relaxed);
                complete_layer(128)
            },
            || true,
        );
        assert!(matches!(
            current,
            DerivedLayerAcquisition::Ready {
                lifecycle: DerivedLayerLifecycle::Built,
                ..
            }
        ));

        let delayed = cache.acquire(
            request,
            &[1],
            &cancellation,
            || {
                builds.fetch_add(1, Ordering::Relaxed);
                complete_layer(128)
            },
            || false,
        );
        assert!(matches!(
            delayed,
            DerivedLayerAcquisition::Unavailable { .. }
        ));
        assert_eq!(builds.load(Ordering::Relaxed), 1);
        assert_eq!(cache.len_for_test(&[1]), 0);
        assert_eq!(cache.len_for_test(&[2]), 1);

        let hit = cache.acquire(
            request,
            &[2],
            &cancellation,
            || {
                builds.fetch_add(1, Ordering::Relaxed);
                complete_layer(128)
            },
            || true,
        );
        assert!(matches!(
            hit,
            DerivedLayerAcquisition::Ready {
                lifecycle: DerivedLayerLifecycle::Hit,
                ..
            }
        ));
        assert_eq!(builds.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn cancelled_and_late_stale_builds_do_not_publish() {
        let cache = SnapshotDerivedLayerCache::new(1024 * 1024);
        let request = DerivedLayerRequest::complete_direct_import_topology();
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let acquisition = cache.acquire(request, &[1], &cancelled, || complete_layer(128), || true);
        assert!(matches!(
            acquisition,
            DerivedLayerAcquisition::Cancelled { .. }
        ));
        assert_eq!(cache.len_for_test(&[1]), 0);

        let cancellation = CancellationToken::default();
        let stale = cache.acquire(
            request,
            &[1],
            &cancellation,
            || complete_layer(128),
            || false,
        );
        assert!(matches!(stale, DerivedLayerAcquisition::Unavailable { .. }));
        assert_eq!(cache.len_for_test(&[1]), 0);
    }

    #[test]
    fn unavailable_build_can_retry() {
        let cache = SnapshotDerivedLayerCache::new(1024 * 1024);
        let request = DerivedLayerRequest::complete_direct_import_topology();
        let cancellation = CancellationToken::default();
        let first = cache.acquire(
            request,
            &[1],
            &cancellation,
            || DerivedLayerBuildOutcome::Unavailable {
                reason: "incomplete".to_string(),
                over_budget: false,
                rejection_scope: None,
                metrics: DerivedLayerBuildMetrics::default(),
            },
            || true,
        );
        assert!(matches!(first, DerivedLayerAcquisition::Unavailable { .. }));
        let retry = cache.acquire(
            request,
            &[1],
            &cancellation,
            || complete_layer(128),
            || true,
        );
        assert!(matches!(
            retry,
            DerivedLayerAcquisition::Ready {
                lifecycle: DerivedLayerLifecycle::Built,
                ..
            }
        ));
    }

    #[test]
    fn auto_rejections_keep_incomparable_request_budgets_and_snapshot_failures() {
        let cache = SnapshotDerivedLayerCache::new(1024 * 1024);
        let request = DerivedLayerRequest::complete_direct_import_topology();
        let generations = [1];

        cache.record_auto_rejection(
            request,
            &generations,
            10,
            100,
            DerivedLayerRejectionScope::RequestBudget,
        );
        cache.record_auto_rejection(
            request,
            &generations,
            100,
            10,
            DerivedLayerRejectionScope::RequestBudget,
        );

        // Each Pareto point suppresses only budgets it dominates.
        assert!(!cache.observe_auto_reuse_opportunity(request, &generations, 5, 50));
        assert!(!cache.observe_auto_reuse_opportunity(request, &generations, 50, 5));
        assert!(!cache.observe_auto_reuse_opportunity(request, &generations, 50, 50));
        assert!(cache.observe_auto_reuse_opportunity(request, &generations, 50, 50));

        cache.record_auto_rejection(
            request,
            &generations,
            usize::MAX,
            usize::MAX,
            DerivedLayerRejectionScope::SnapshotBudget,
        );
        assert!(!cache.observe_auto_reuse_opportunity(
            request,
            &generations,
            usize::MAX,
            usize::MAX
        ));
    }

    fn wait_for_follower(cache: &SnapshotDerivedLayerCache, source_generation: u64) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while cache.waiting_count_for_test(&[source_generation]) == 0 {
            assert!(
                Instant::now() < deadline,
                "same-key derived request did not enter the single-flight wait"
            );
            thread::yield_now();
        }
    }

    #[test]
    fn same_key_builds_once_and_cancelled_follower_does_not_cancel_leader() {
        let cache = Arc::new(SnapshotDerivedLayerCache::new(1024 * 1024));
        let request = DerivedLayerRequest::complete_direct_import_topology();
        let builds = Arc::new(AtomicUsize::new(0));
        let (leader_started_tx, leader_started_rx) = mpsc::channel();
        let (release_leader_tx, release_leader_rx) = mpsc::channel();

        let leader_cache = Arc::clone(&cache);
        let leader_builds = Arc::clone(&builds);
        let leader = thread::spawn(move || {
            leader_cache.acquire(
                request,
                &[1],
                &CancellationToken::default(),
                || {
                    leader_builds.fetch_add(1, Ordering::Relaxed);
                    leader_started_tx.send(()).expect("signal leader start");
                    release_leader_rx.recv().expect("release leader");
                    complete_layer(128)
                },
                || true,
            )
        });
        leader_started_rx.recv().expect("leader started");

        let follower_cancellation = CancellationToken::default();
        let follower_token = follower_cancellation.clone();
        let follower_cache = Arc::clone(&cache);
        let follower_builds = Arc::clone(&builds);
        let follower = thread::spawn(move || {
            follower_cache.acquire(
                request,
                &[1],
                &follower_token,
                || {
                    follower_builds.fetch_add(1, Ordering::Relaxed);
                    complete_layer(128)
                },
                || true,
            )
        });
        wait_for_follower(&cache, 1);
        follower_cancellation.cancel();
        let cancelled = follower.join().expect("cancelled follower");
        assert!(matches!(
            cancelled,
            DerivedLayerAcquisition::Cancelled { .. }
        ));

        release_leader_tx.send(()).expect("release leader build");
        let built = leader.join().expect("leader thread");
        assert!(matches!(
            built,
            DerivedLayerAcquisition::Ready {
                lifecycle: DerivedLayerLifecycle::Built,
                ..
            }
        ));
        assert_eq!(builds.load(Ordering::Relaxed), 1);

        let hit = cache.acquire(
            request,
            &[1],
            &CancellationToken::default(),
            || {
                builds.fetch_add(1, Ordering::Relaxed);
                complete_layer(128)
            },
            || true,
        );
        assert!(matches!(
            hit,
            DerivedLayerAcquisition::Ready {
                lifecycle: DerivedLayerLifecycle::Hit,
                ..
            }
        ));
        assert_eq!(builds.load(Ordering::Relaxed), 1);
    }

    fn completed_topology(build: DirectImportTopologyBuild) -> DirectImportTopology {
        assert!(build.fallback.is_none());
        match build.outcome {
            DerivedLayerBuildOutcome::Complete {
                layer: DerivedLayer::DirectImportTopology(topology),
                ..
            } => topology,
            DerivedLayerBuildOutcome::Cancelled { .. }
            | DerivedLayerBuildOutcome::Unavailable { .. } => {
                panic!("expected complete direct import topology")
            }
        }
    }

    fn generous_limits() -> DirectImportTopologyLimits {
        DirectImportTopologyLimits {
            max_files: 100,
            max_edges: 100,
            max_retained_bytes: 1024 * 1024,
        }
    }

    #[test]
    fn topology_deduplicates_cycle_edges_and_orders_neighbors() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let a = ProjectFile::new(root.clone(), PathBuf::from("a.rb"));
        let b = ProjectFile::new(root.clone(), PathBuf::from("b.rb"));
        let c = ProjectFile::new(root.clone(), PathBuf::from("c.rb"));
        a.write(
            "require_relative 'c'\nrequire_relative 'b'\nrequire_relative 'b'\ndef from_a; end\n",
        )
        .expect("write a");
        b.write("require_relative 'a'\ndef from_b; end\n")
            .expect("write b");
        c.write("def from_c; end\n").expect("write c");
        let analyzer = RubyAnalyzer::from_project(TestProject::new(root, Language::Ruby));

        let first = completed_topology(build_direct_import_topology(
            &analyzer,
            &CancellationToken::default(),
            generous_limits(),
        ));
        let second = completed_topology(build_direct_import_topology(
            &analyzer,
            &CancellationToken::default(),
            generous_limits(),
        ));

        assert_eq!(first.resolved_files(), 3);
        assert_eq!(first.resolved_edges(), 3);
        assert_eq!(
            first
                .imports_of(&a)
                .expect("supported source")
                .iter()
                .map(rel_path_string)
                .collect::<Vec<_>>(),
            vec!["b.rb", "c.rb"]
        );
        assert_eq!(
            first
                .importers_of(&a)
                .expect("complete reverse relation")
                .iter()
                .map(rel_path_string)
                .collect::<Vec<_>>(),
            vec!["b.rb"]
        );
        for file in [&a, &b, &c] {
            assert_eq!(first.imports_of(file), second.imports_of(file));
            assert_eq!(first.importers_of(file), second.importers_of(file));
        }
        assert_eq!(first.retained_bytes(), second.retained_bytes());
    }

    #[test]
    fn unsupported_sources_prevent_exact_reverse_reuse() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = ProjectFile::new(root.clone(), PathBuf::from("app.php"));
        file.write("<?php\nfunction target() {}\n")
            .expect("write source");
        let analyzer = PhpAnalyzer::from_project(TestProject::new(root, Language::Php));

        let topology = completed_topology(build_direct_import_topology(
            &analyzer,
            &CancellationToken::default(),
            generous_limits(),
        ));

        assert_eq!(topology.resolved_files(), 1);
        assert_eq!(topology.resolved_edges(), 0);
        assert!(!topology.reverse_relation_complete());
        assert_eq!(topology.imports_of(&file), None);
        assert_eq!(topology.importers_of(&file), None);
    }

    #[test]
    fn topology_limits_reject_without_returning_partial_edges() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), PathBuf::from("bench/Target.java"))
            .write("package bench; public class Target {}\n")
            .expect("write target");
        ProjectFile::new(root.clone(), PathBuf::from("bench/Consumer.java"))
            .write("package bench; import bench.Target; public class Consumer {}\n")
            .expect("write consumer");
        let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));

        let outcome = build_direct_import_topology(
            &analyzer,
            &CancellationToken::default(),
            DirectImportTopologyLimits {
                max_files: 100,
                max_edges: 0,
                max_retained_bytes: 1024 * 1024,
            },
        );

        assert!(matches!(
            outcome.outcome,
            DerivedLayerBuildOutcome::Unavailable {
                over_budget: true,
                ..
            }
        ));
        assert!(outcome.fallback.is_some());
    }

    #[test]
    fn topology_construction_preflights_fixed_memory_before_resolution() {
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "bench/Target.java")
            .write("package bench; public class Target {}\n")
            .expect("write target");
        let analyzer = JavaAnalyzer::from_project(TestProject::new(root, Language::Java));

        let build = build_direct_import_topology(
            &analyzer,
            &CancellationToken::default(),
            DirectImportTopologyLimits {
                max_files: 100,
                max_edges: 100,
                max_retained_bytes: 1,
            },
        );

        assert!(matches!(
            build.outcome,
            DerivedLayerBuildOutcome::Unavailable {
                over_budget: true,
                metrics: DerivedLayerBuildMetrics {
                    resolved_files: 0,
                    resolved_edges: 0,
                    ..
                },
                ..
            }
        ));
        assert!(build.fallback.is_none());
    }
}
