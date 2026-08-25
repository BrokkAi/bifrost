use serde::{Serialize, Serializer};
use std::collections::BTreeMap;
use std::mem::size_of;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::analyzer::complete_value_cache::{
    CompleteValueAcquisition, CompleteValueCache, CompleteValueWait,
};
use crate::analyzer::content_identity::WorkspaceContentIdentity;
use crate::analyzer::invalidation::{
    ArtifactVerdict, ArtifactVerdictLog, DerivedArtifactId, DerivedArtifactKind,
    InvalidationReason, RetentionReason,
};
use crate::analyzer::semantic::ids::StableDigest;
use crate::analyzer::{IAnalyzer, Language, ProjectFile};
use crate::cancellation::CancellationToken;
use crate::compact_graph::CompactDirectedGraph;
use crate::hash::{HashMap, HashSet};
use crate::path_utils::rel_path_string;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::query_token::QueryToken;

/// The semantic family of one reusable, immutable query-execution layer.
///
/// A runtime layer owner must define its complete validity key next to its
/// materializer. See `CompleteValueCache` for the required key dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivedLayerKind {
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
pub struct DerivedLayerRequest {
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
    pub fn complete_direct_import_topology() -> Self {
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
pub enum DerivedLayer {
    DirectImportTopology(DirectImportTopology),
}

impl DerivedLayer {
    pub fn direct_import_topology(&self) -> &DirectImportTopology {
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
pub struct DerivedLayerBuildMetrics {
    pub resolved_files: u64,
    pub resolved_edges: u64,
    pub elapsed_ns: u64,
    pub retained_bytes: u64,
}

pub enum DerivedLayerBuildOutcome {
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
pub enum DerivedLayerRejectionScope {
    RequestBudget,
    SnapshotBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivedLayerLifecycle {
    Hit,
    Built,
}

pub enum DerivedLayerAcquisition {
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

/// One bound derived-layer cache key: what was asked for, and the workspace
/// content it must have been derived from (#2449).
///
/// Before this the backing cache was keyed by the request alone and the whole
/// cache was rotated whenever the process's source-generation vector moved,
/// which discarded every relation on every edit anywhere in the workspace and
/// made cross-branch reuse impossible. Binding the content into the key instead
/// means a value is never wrong and never needs rotating: a key nothing asks
/// for again is retired by the byte budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DerivedLayerKey {
    request: DerivedLayerRequest,
    workspace_content: WorkspaceContentIdentity,
}

impl DerivedLayerKey {
    const ARTIFACT_DOMAIN: &[u8] = b"bifrost-derived-layer-key:v1";

    fn artifact(self) -> DerivedArtifactId {
        let mut hasher = CanonicalHasher::new(Self::ARTIFACT_DOMAIN);
        hasher.field(
            "kind",
            match self.request.kind {
                DerivedLayerKind::DirectImportTopology => b"direct_import_topology",
            },
        );
        hasher.field(
            "projection_filter",
            self.request.projection_filter_fingerprint.as_bytes(),
        );
        hasher.field(
            "representation_version",
            &self.request.representation_version.to_be_bytes(),
        );
        hasher.field("content", self.workspace_content.digest().as_bytes());
        DerivedArtifactId::new(
            DerivedArtifactKind::DerivedQueryLayer,
            StableDigest::from_array(hasher.finish()),
        )
    }
}

/// The Auto-admission observations one workspace content identity accumulated.
///
/// These are request-budget bookkeeping rather than derived values, so they are
/// held beside the values in a small bounded map: an observation for content
/// nobody asks about again is dropped once
/// [`SnapshotDerivedLayerCache::MAX_OBSERVED_CONTENTS`] newer identities have
/// been seen, and losing one costs at most one extra fallback.
#[derive(Default)]
struct DerivedLayerObservations {
    auto_reuse_requests: HashSet<DerivedLayerRequest>,
    auto_rejections: HashMap<DerivedLayerRequest, Vec<(usize, usize)>>,
    snapshot_rejections: HashSet<DerivedLayerRequest>,
}

/// Snapshot-owned complete derived values with content-keyed single-flight.
///
/// The authored request stays representation-neutral; the workspace content
/// identity binds it to the exact analyzed content a value was derived from.
/// A mutable overlay can advance without replacing the analyzer object, so the
/// caller still supplies a `content_is_current` predicate and a late build
/// against content that has moved is refused rather than published.
pub struct SnapshotDerivedLayerCache {
    max_retained_bytes: u64,
    values: CompleteValueCache<DerivedLayerKey, DerivedLayer>,
    observations: Mutex<Vec<(WorkspaceContentIdentity, DerivedLayerObservations)>>,
    verdicts: ArtifactVerdictLog,
}

impl SnapshotDerivedLayerCache {
    pub const DEFAULT_MAX_RETAINED_BYTES: u64 = 32 * 1024 * 1024;
    /// How many workspace content identities keep their Auto observations.
    /// Small: an analyzer answers about one content at a time, and the previous
    /// one only matters while an in-flight request still holds it.
    const MAX_OBSERVED_CONTENTS: usize = 4;

    pub fn new(max_retained_bytes: u64) -> Self {
        Self {
            max_retained_bytes,
            values: CompleteValueCache::new(max_retained_bytes, |_, layer: &Arc<DerivedLayer>| {
                layer.retained_bytes().clamp(1, u32::MAX as u64) as u32
            }),
            observations: Mutex::new(Vec::new()),
            verdicts: ArtifactVerdictLog::default(),
        }
    }

    pub fn verdicts(&self) -> &ArtifactVerdictLog {
        &self.verdicts
    }

    /// Record that a caller could not state a workspace content identity, so
    /// this cache was not consulted at all.
    pub fn record_missing_content_identity(&self, request: DerivedLayerRequest) {
        self.verdicts.record(ArtifactVerdict::Invalidated(
            InvalidationReason::ContentIdentityEvidenceMissing {
                artifact: DerivedLayerKey {
                    request,
                    workspace_content: WorkspaceContentIdentity::unattested(),
                }
                .artifact(),
            },
        ));
    }

    fn with_observations<T>(
        &self,
        workspace_content: WorkspaceContentIdentity,
        use_observations: impl FnOnce(&mut DerivedLayerObservations) -> T,
    ) -> T {
        let mut observations = self
            .observations
            .lock()
            .expect("snapshot derived-layer observation mutex poisoned");
        if let Some(position) = observations
            .iter()
            .position(|(content, _)| *content == workspace_content)
        {
            // Most-recently-used last, so the truncation below drops the
            // identity nothing has asked about for longest.
            let entry = observations.remove(position);
            observations.push(entry);
        } else {
            observations.push((workspace_content, DerivedLayerObservations::default()));
            while observations.len() > Self::MAX_OBSERVED_CONTENTS {
                observations.remove(0);
            }
        }
        let (_, entry) = observations
            .last_mut()
            .expect("an observation entry was just installed");
        use_observations(entry)
    }

    pub fn get_ready(
        &self,
        request: DerivedLayerRequest,
        workspace_content: WorkspaceContentIdentity,
        cancellation: &CancellationToken,
    ) -> Option<Arc<DerivedLayer>> {
        let key = DerivedLayerKey {
            request,
            workspace_content,
        };
        let ready = self.values.get_ready(&key, cancellation);
        self.verdicts.record(match ready {
            Some(_) => ArtifactVerdict::Retained(RetentionReason::InputsUnchanged {
                artifact: key.artifact(),
            }),
            None => ArtifactVerdict::Invalidated(InvalidationReason::NoRetainedArtifact {
                artifact: key.artifact(),
            }),
        });
        ready
    }

    pub fn max_retained_bytes(&self) -> u64 {
        self.max_retained_bytes
    }

    /// Auto avoids constructing a whole-workspace relation for a one-off
    /// query. The first viable request records reuse interest and falls back;
    /// a later request for the same content and representation may build.
    pub fn observe_auto_reuse_opportunity(
        &self,
        request: DerivedLayerRequest,
        workspace_content: WorkspaceContentIdentity,
        max_files: usize,
        max_edges: usize,
    ) -> bool {
        self.with_observations(workspace_content, |observations| {
            if observations.snapshot_rejections.contains(&request)
                || observations
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
            !observations.auto_reuse_requests.insert(request)
        })
    }

    pub fn record_auto_rejection(
        &self,
        request: DerivedLayerRequest,
        workspace_content: WorkspaceContentIdentity,
        max_files: usize,
        max_edges: usize,
        scope: DerivedLayerRejectionScope,
    ) {
        self.with_observations(workspace_content, |observations| {
            if scope == DerivedLayerRejectionScope::SnapshotBudget {
                observations.snapshot_rejections.insert(request);
                observations.auto_rejections.remove(&request);
                return;
            }
            let rejections = observations.auto_rejections.entry(request).or_default();
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

    pub fn acquire(
        &self,
        request: DerivedLayerRequest,
        workspace_content: WorkspaceContentIdentity,
        cancellation: &CancellationToken,
        build: impl FnOnce() -> DerivedLayerBuildOutcome,
        content_is_current: impl Fn() -> bool,
    ) -> DerivedLayerAcquisition {
        let key = DerivedLayerKey {
            request,
            workspace_content,
        };
        let values = &self.values;
        let (acquisition, wait) = values.acquire(&key, cancellation);
        match acquisition {
            CompleteValueAcquisition::Cached { value } => {
                if !content_is_current() {
                    return DerivedLayerAcquisition::Unavailable {
                        reason: "derived-layer workspace content changed before reuse".to_string(),
                        over_budget: false,
                        rejection_scope: None,
                        wait,
                        build: DerivedLayerBuildMetrics::default(),
                    };
                }
                self.verdicts.record(ArtifactVerdict::Retained(
                    RetentionReason::InputsUnchanged {
                        artifact: key.artifact(),
                    },
                ));
                DerivedLayerAcquisition::Ready {
                    layer: value,
                    lifecycle: DerivedLayerLifecycle::Hit,
                    wait,
                    build: DerivedLayerBuildMetrics::default(),
                }
            }
            CompleteValueAcquisition::Leader { permit } => {
                self.verdicts.record(ArtifactVerdict::Invalidated(
                    InvalidationReason::NoRetainedArtifact {
                        artifact: key.artifact(),
                    },
                ));
                match build() {
                    DerivedLayerBuildOutcome::Complete { layer, mut metrics } => {
                        metrics.retained_bytes = layer.retained_bytes();
                        if cancellation.is_cancelled() {
                            return DerivedLayerAcquisition::Cancelled {
                                wait,
                                build: metrics,
                            };
                        }
                        if !content_is_current() {
                            permit.publish_rejected();
                            return DerivedLayerAcquisition::Unavailable {
                                reason: "derived-layer workspace content changed during build"
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
                        if !content_is_current() {
                            return DerivedLayerAcquisition::Unavailable {
                                reason:
                                    "derived-layer workspace content changed during publication"
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
                        let content_is_current = content_is_current();
                        if rejection_scope.is_some() {
                            permit.publish_rejected();
                        }
                        if !content_is_current {
                            DerivedLayerAcquisition::Unavailable {
                                reason:
                                    "derived-layer workspace content changed during failed build"
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
                }
            }
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
    pub fn len_for_test(&self) -> u64 {
        self.values.len_for_test()
    }

    #[cfg(test)]
    fn waiting_count_for_test(&self) -> usize {
        self.values.waiting_count_for_test()
    }
}

impl Default for SnapshotDerivedLayerCache {
    fn default() -> Self {
        Self::new(Self::DEFAULT_MAX_RETAINED_BYTES)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DirectImportTopologyLimits {
    pub max_files: usize,
    pub max_edges: usize,
    pub max_retained_bytes: u64,
}

pub struct DirectImportTopologyBuild {
    pub outcome: DerivedLayerBuildOutcome,
    pub fallback: Option<RequestLocalDirectImportGraph>,
}

/// Complete import resolution for every analyzed file in one declared support
/// domain. Unsupported files are retained as dense support bits; the reverse
/// relation is exact only when all possible source files were supported.
#[derive(Debug)]
pub struct DirectImportTopology {
    graph: CompactDirectedGraph<ProjectFile>,
    supported_sources: Box<[bool]>,
    resolved_files: usize,
    retained_bytes: u64,
}

impl DirectImportTopology {
    pub fn imports_of(&self, file: &ProjectFile) -> Option<Vec<ProjectFile>> {
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

    pub fn known_importers_of(&self, file: &ProjectFile) -> Vec<ProjectFile> {
        let Some(target) = self.graph.node_id(file) else {
            return Vec::new();
        };
        self.graph
            .incoming(target)
            .iter()
            .map(|source| self.graph.nodes()[*source as usize].clone())
            .collect()
    }

    pub fn import_count(&self, file: &ProjectFile) -> Option<usize> {
        let source = self.graph.node_id(file)?;
        self.supported_sources[source as usize].then(|| self.graph.outgoing(source).len())
    }

    pub fn known_importer_count(&self, file: &ProjectFile) -> usize {
        self.graph
            .node_id(file)
            .map_or(0, |target| self.graph.incoming(target).len())
    }

    pub fn reverse_relation_complete(&self) -> bool {
        self.supported_sources.iter().all(|supported| *supported)
    }

    pub fn unsupported_languages(&self) -> Vec<Language> {
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

    pub fn resolved_files(&self) -> usize {
        self.resolved_files
    }

    pub fn resolved_edges(&self) -> usize {
        self.graph.edge_count()
    }

    pub fn retained_bytes(&self) -> u64 {
        self.retained_bytes
    }
}

pub fn build_direct_import_topology(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
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
        token,
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
pub struct RequestLocalDirectImportGraph {
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
    pub fn new(analyzer: &dyn IAnalyzer) -> Self {
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

    pub fn imports_of(&self, file: &ProjectFile) -> Vec<ProjectFile> {
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

    pub fn supports_source(&self, file: &ProjectFile) -> bool {
        !self.unsupported.contains(file)
    }

    pub fn importers_of(&self, file: &ProjectFile) -> Vec<ProjectFile> {
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

    pub fn importer_count(&self, file: &ProjectFile) -> usize {
        let Some(compact) = &self.compact else {
            return 0;
        };
        compact
            .node_id(file)
            .map_or(0, |target| compact.incoming(target).len())
    }

    pub fn forward_relation_complete(&self, files: &[ProjectFile]) -> bool {
        files.iter().all(|file| self.forward.contains_key(file))
    }

    pub fn has_cached_forward(&self, file: &ProjectFile) -> bool {
        self.forward.contains_key(file)
            || self.unsupported.contains(file)
            || self.budget_omitted.contains(file)
    }

    pub fn cached_forward_edge_count(&self, file: &ProjectFile) -> usize {
        self.forward.get(file).map_or(0, Vec::len)
    }

    pub fn reverse_relation_complete(&self) -> bool {
        self.complete && self.unsupported.is_empty()
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn unsupported_languages(&self) -> Vec<Language> {
        let mut languages = self
            .unsupported
            .iter()
            .map(crate::analyzer::common::language_for_file)
            .collect::<Vec<_>>();
        languages.sort();
        languages.dedup();
        languages
    }

    pub fn resolved_files(&self) -> usize {
        self.attempted_files
    }

    pub fn resolved_edges(&self) -> usize {
        self.attempted_edges
    }

    pub fn ensure_complete(
        &mut self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
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
            token,
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
        token: QueryToken<'_>,
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
            token,
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

    pub fn ensure_forward(
        &mut self,
        analyzer: &dyn IAnalyzer,
        token: QueryToken<'_>,
        files: &[ProjectFile],
        max_files: usize,
        max_edges: usize,
        cancellation: Option<&CancellationToken>,
    ) -> bool {
        self.ensure_forward_inner(
            analyzer,
            token,
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
        token: QueryToken<'_>,
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
                        owned_imports = provider.import_info_of(token, file);
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
    use crate::analyzer::{AnalyzerQueryScope, QueryScope};
    use crate::analyzer::{JavaAnalyzer, PhpAnalyzer, RubyAnalyzer, TestProject};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    fn content(seed: u64) -> WorkspaceContentIdentity {
        WorkspaceContentIdentity::for_test(seed)
    }

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

    /// Milestone J (#2449): the cache is keyed by workspace content, so a
    /// second content builds beside the first instead of rotating it away, and
    /// returning to the first content still hits. That is the cross-branch and
    /// undo case the old whole-cache rotation could not serve.
    #[test]
    fn snapshot_cache_reuses_by_workspace_content_and_retains_both() {
        let cache = SnapshotDerivedLayerCache::new(1024 * 1024);
        let request = DerivedLayerRequest::complete_direct_import_topology();
        let cancellation = CancellationToken::default();
        let builds = AtomicUsize::new(0);

        let first = cache.acquire(
            request,
            content(1),
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
            content(1),
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
            content(2),
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
        assert_eq!(cache.len_for_test(), 2);

        let returned = cache.acquire(
            request,
            content(1),
            &cancellation,
            || panic!("returning to retained content must not rebuild"),
            || true,
        );
        assert!(matches!(
            returned,
            DerivedLayerAcquisition::Ready {
                lifecycle: DerivedLayerLifecycle::Hit,
                ..
            }
        ));
    }

    /// A build whose workspace content moved while it ran is refused rather
    /// than published, even though its key names content the cache would
    /// otherwise be willing to retain.
    #[test]
    fn a_late_build_against_content_that_moved_is_never_published() {
        let cache = SnapshotDerivedLayerCache::new(1024 * 1024);
        let request = DerivedLayerRequest::complete_direct_import_topology();
        let cancellation = CancellationToken::default();
        let builds = AtomicUsize::new(0);

        let current = cache.acquire(
            request,
            content(2),
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
            content(1),
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
        assert_eq!(builds.load(Ordering::Relaxed), 2);
        assert_eq!(
            cache.len_for_test(),
            1,
            "only the acquisition whose content stayed current is retained"
        );

        let hit = cache.acquire(
            request,
            content(2),
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
        assert_eq!(builds.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn cancelled_and_late_stale_builds_do_not_publish() {
        let cache = SnapshotDerivedLayerCache::new(1024 * 1024);
        let request = DerivedLayerRequest::complete_direct_import_topology();
        let cancelled = CancellationToken::default();
        cancelled.cancel();
        let acquisition = cache.acquire(
            request,
            content(1),
            &cancelled,
            || complete_layer(128),
            || true,
        );
        assert!(matches!(
            acquisition,
            DerivedLayerAcquisition::Cancelled { .. }
        ));
        assert_eq!(cache.len_for_test(), 0);

        let cancellation = CancellationToken::default();
        let stale = cache.acquire(
            request,
            content(1),
            &cancellation,
            || complete_layer(128),
            || false,
        );
        assert!(matches!(stale, DerivedLayerAcquisition::Unavailable { .. }));
        assert_eq!(cache.len_for_test(), 0);
    }

    /// Milestone J (#2449): every reuse or rebuild decision is recorded, and a
    /// caller with no content identity widens to a rebuild with the typed
    /// reason rather than reusing a value it cannot prove current.
    #[test]
    fn every_decision_records_a_verdict_and_a_missing_identity_widens() {
        let cache = SnapshotDerivedLayerCache::new(1024 * 1024);
        let request = DerivedLayerRequest::complete_direct_import_topology();
        let cancellation = CancellationToken::default();

        cache.acquire(
            request,
            content(1),
            &cancellation,
            || complete_layer(128),
            || true,
        );
        cache.acquire(
            request,
            content(1),
            &cancellation,
            || panic!("warm acquisition must not rebuild"),
            || true,
        );
        cache.record_missing_content_identity(request);

        let (retained, invalidated) = cache.verdicts().totals();
        assert_eq!((1, 2), (retained, invalidated));
        let labels = cache
            .verdicts()
            .recent()
            .iter()
            .map(|verdict| verdict.stable_label())
            .collect::<Vec<_>>();
        assert_eq!(
            vec![
                "no_retained_artifact",
                "inputs_unchanged",
                "content_identity_evidence_missing",
            ],
            labels
        );
    }

    #[test]
    fn unavailable_build_can_retry() {
        let cache = SnapshotDerivedLayerCache::new(1024 * 1024);
        let request = DerivedLayerRequest::complete_direct_import_topology();
        let cancellation = CancellationToken::default();
        let first = cache.acquire(
            request,
            content(1),
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
            content(1),
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
        let workspace_content = content(1);

        cache.record_auto_rejection(
            request,
            workspace_content,
            10,
            100,
            DerivedLayerRejectionScope::RequestBudget,
        );
        cache.record_auto_rejection(
            request,
            workspace_content,
            100,
            10,
            DerivedLayerRejectionScope::RequestBudget,
        );

        // Each Pareto point suppresses only budgets it dominates.
        assert!(!cache.observe_auto_reuse_opportunity(request, workspace_content, 5, 50));
        assert!(!cache.observe_auto_reuse_opportunity(request, workspace_content, 50, 5));
        assert!(!cache.observe_auto_reuse_opportunity(request, workspace_content, 50, 50));
        assert!(cache.observe_auto_reuse_opportunity(request, workspace_content, 50, 50));

        cache.record_auto_rejection(
            request,
            workspace_content,
            usize::MAX,
            usize::MAX,
            DerivedLayerRejectionScope::SnapshotBudget,
        );
        assert!(!cache.observe_auto_reuse_opportunity(
            request,
            workspace_content,
            usize::MAX,
            usize::MAX
        ));
    }

    fn wait_for_follower(cache: &SnapshotDerivedLayerCache) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while cache.waiting_count_for_test() == 0 {
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
                content(1),
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
                content(1),
                &follower_token,
                || {
                    follower_builds.fetch_add(1, Ordering::Relaxed);
                    complete_layer(128)
                },
                || true,
            )
        });
        wait_for_follower(&cache);
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
            content(1),
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

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let first = completed_topology(build_direct_import_topology(
            &analyzer,
            token,
            &CancellationToken::default(),
            generous_limits(),
        ));
        let second = completed_topology(build_direct_import_topology(
            &analyzer,
            token,
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

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let topology = completed_topology(build_direct_import_topology(
            &analyzer,
            token,
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

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let outcome = build_direct_import_topology(
            &analyzer,
            token,
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

        let scope = AnalyzerQueryScope::new(&analyzer);
        let token = scope.token();
        let build = build_direct_import_topology(
            &analyzer,
            token,
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
