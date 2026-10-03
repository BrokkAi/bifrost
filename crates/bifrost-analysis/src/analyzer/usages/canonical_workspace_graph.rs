//! Canonical selected-resolution workspace graph projection.
//!
//! The legacy workspace graph remains in the parent module. This module owns
//! the selected canonical path so its eventual cutover is a module operation.

use std::collections::BTreeMap;

use super::super::inverted_edges::MAX_CALLSITES;
use super::super::{ReferenceKind, UsageHitKind, UsageHitSurface, UsageProof};
use super::*;
use crate::analyzer::resolution::ResolutionBatchMetrics;
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::{
    BindingFragmentId, FactReferenceEdgeCatalog, FactReferenceEdgeDeclarationDomain,
    FactReferenceEdgeDomainStatus, FactResolutionSource, SelectedFactResolutionSnapshot,
    stage_selected_reference_edge_batches, validate_selected_reference_edge_coverage,
};
use crate::analyzer::store::{Result as StoreResult, StoreError};
use crate::analyzer::structural::reference_edges::{
    EdgeCompleteness, EdgeIncompleteReason, ReferenceEdgeRow,
};
use crate::analyzer::structural::{EdgeAxis, EdgeProvenance};
use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageReferenceKind;

/// Canonical-only metadata layered over the unchanged legacy graph catalog.
///
/// Full declaration spans and analyzer generation are needed only while
/// reducing canonical forward rows. Keeping them here preserves the legacy
/// node layout and its primary-range-only construction path byte for byte.
struct CanonicalWorkspaceUsageCatalog {
    catalog: WorkspaceUsageCatalog,
    declaration_spans_by_node: Vec<Vec<(ProjectFile, Range)>>,
    generation: u64,
}

impl CanonicalWorkspaceUsageCatalog {
    #[cfg(any(test, feature = "test-support"))]
    fn build_with_cancellation(
        analyzer: &dyn IAnalyzer,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let generation = analyzer.project().analysis_generation();
        let is_current = || {
            !cancellation.is_cancelled() && analyzer.project().analysis_generation() == generation
        };
        if !is_current() {
            return None;
        }

        let mut files = analyzer.analyzed_files();
        if !is_current() {
            return None;
        }
        files.sort();
        files.dedup();

        let mut declarations = Vec::new();
        for file in files {
            if !is_current() {
                return None;
            }
            let projection = analyzer.summary_file_projection(&file);
            if !is_current() {
                return None;
            }
            let mut seen = HashSet::default();
            if let Some(projection) = projection.as_ref() {
                let mut stack = projection.top_level_declarations.clone();
                stack.extend(projection.signatures.keys().cloned());
                stack.extend(projection.ranges.keys().cloned());
                stack.extend(projection.children.keys().cloned());
                stack.extend(
                    projection
                        .children
                        .values()
                        .flat_map(|children| children.iter().cloned()),
                );
                while let Some(unit) = stack.pop() {
                    if !is_current() {
                        return None;
                    }
                    if !seen.insert(unit.clone()) {
                        continue;
                    }
                    if let Some(children) = projection.children.get(&unit) {
                        stack.extend(children.iter().cloned());
                    }
                    if is_graph_declaration(&unit) {
                        declarations.push((
                            unit.clone(),
                            projection.ranges.get(&unit).cloned().unwrap_or_default(),
                        ));
                    }
                }
            } else {
                let file_declarations = analyzer.declarations(&file);
                if !is_current() {
                    return None;
                }
                for unit in file_declarations {
                    if !is_current() {
                        return None;
                    }
                    if !seen.insert(unit.clone()) || !is_graph_declaration(&unit) {
                        continue;
                    }
                    let ranges = analyzer.ranges(&unit);
                    if !is_current() {
                        return None;
                    }
                    declarations.push((unit, ranges));
                }
            }

            if is_java_module_descriptor_file(&file) {
                let file_scope = CodeUnit::file_scope(file.clone());
                if seen.insert(file_scope.clone()) {
                    let ranges = projection
                        .as_ref()
                        .and_then(|projection| projection.ranges.get(&file_scope).cloned())
                        .unwrap_or_else(|| analyzer.ranges(&file_scope));
                    if !is_current() {
                        return None;
                    }
                    declarations.push((file_scope, ranges));
                }
            }
        }

        let catalog =
            Self::from_declarations_with_all_ranges(declarations, generation, cancellation)?;
        is_current().then_some(catalog)
    }

    fn from_declarations_with_all_ranges(
        declarations: Vec<(CodeUnit, Vec<Range>)>,
        generation: u64,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let mut primary_declarations = Vec::with_capacity(declarations.len());
        for (unit, ranges) in &declarations {
            if cancellation.is_cancelled() {
                return None;
            }
            primary_declarations.push((unit.clone(), primary_range(ranges)));
        }
        let catalog = WorkspaceUsageCatalog::from_declarations(primary_declarations, cancellation)?;
        let mut declaration_spans_by_node = vec![Vec::new(); catalog.nodes.len()];
        for (unit, ranges) in declarations {
            if cancellation.is_cancelled() {
                return None;
            }
            let index = catalog
                .index_for_id(&unit.declaration_id())
                .expect("every canonical declaration belongs to its legacy-shaped graph node");
            for range in ranges {
                if cancellation.is_cancelled() {
                    return None;
                }
                declaration_spans_by_node[index].push((unit.source().clone(), range));
            }
        }
        for spans in &mut declaration_spans_by_node {
            if cancellation.is_cancelled() {
                return None;
            }
            spans.sort_by(|(left_file, left), (right_file, right)| {
                left_file
                    .cmp(right_file)
                    .then_with(|| range_key(left).cmp(&range_key(right)))
                    .then_with(|| left.end_byte.cmp(&right.end_byte))
                    .then_with(|| left.end_line.cmp(&right.end_line))
            });
            spans.dedup();
        }
        if cancellation.is_cancelled() {
            return None;
        }
        Some(Self {
            catalog,
            declaration_spans_by_node,
            generation,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    fn nodes(&self) -> &[WorkspaceUsageNode] {
        &self.catalog.nodes
    }

    #[cfg(test)]
    fn index_for_id(&self, id: &DeclarationId) -> Option<usize> {
        self.catalog.index_for_id(id)
    }

    #[cfg(test)]
    fn declaration_spans(&self, index: usize) -> &[(ProjectFile, Range)] {
        &self.declaration_spans_by_node[index]
    }
}

/// The result of reducing one complete generation of canonical forward rows.
///
/// `Incomplete` retains the sound positive inventory for the current request,
/// but callers must not cache or interpret absence from that graph as proof.
#[cfg(test)]
pub(crate) enum CanonicalWorkspaceUsageGraphBuildOutcome {
    Complete(WorkspaceUsageGraph),
    Incomplete(WorkspaceUsageGraph),
    Cancelled,
}

/// One exact public-site projection retained beside the ranking edge counts.
///
/// The ranking consumer needs only the strongest reference-kind count per
/// `(caller, target, file, line)`. The public usage-graph result additionally
/// promises the sorted file/line inventory behind each edge. Keeping that
/// inventory in the same reducer prevents a benchmark-only transpose from
/// drifting from graph admission, call-site caps, or self-edge handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalWorkspaceUsageProjectedEdge {
    pub(crate) from: usize,
    pub(crate) to: usize,
    pub(crate) counts: UsageReferenceCounts,
    pub(crate) sites: Vec<(ProjectFile, usize)>,
}

type CanonicalProjectedEdgesByNodePair =
    BTreeMap<(usize, usize), (UsageReferenceCounts, BTreeSet<(ProjectFile, usize)>)>;

struct CanonicalWorkspaceUsageGraphProjection {
    nodes: Vec<WorkspaceUsageNode>,
    edges: Vec<CanonicalWorkspaceUsageProjectedEdge>,
    raw_proven_inbound: Vec<usize>,
    admitted_callers: HashSet<ProjectFile>,
    unresolved_names: Option<BTreeSet<String>>,
    forward_completeness: EdgeCompleteness,
    kind_projection_complete: bool,
    #[cfg(test)]
    resolved_ecosystems: Vec<UsageEcosystem>,
}

#[cfg(test)]
impl CanonicalWorkspaceUsageGraphProjection {
    fn into_workspace_graph(self, cancellation: &CancellationToken) -> Option<WorkspaceUsageGraph> {
        let edges = projected_edges_into_ranking_edges(&self.nodes, self.edges, cancellation)?;
        Some(WorkspaceUsageGraph {
            nodes: self.nodes,
            edges,
            #[cfg(test)]
            resolved_ecosystems: self.resolved_ecosystems,
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
fn projected_edges_into_ranking_edges(
    nodes: &[WorkspaceUsageNode],
    edges: Vec<CanonicalWorkspaceUsageProjectedEdge>,
    cancellation: &CancellationToken,
) -> Option<Vec<WorkspaceUsageEdge>> {
    let mut ranking_edges = Vec::with_capacity(edges.len());
    for edge in edges {
        if cancellation.is_cancelled() {
            return None;
        }
        if nodes[edge.to].truncated_inbound.is_some() {
            continue;
        }
        ranking_edges.push(WorkspaceUsageEdge {
            from: edge.from,
            to: edge.to,
            counts: edge.counts,
        });
    }
    Some(ranking_edges)
}

enum CanonicalWorkspaceUsageGraphProjectionOutcome {
    Complete(CanonicalWorkspaceUsageGraphProjection),
    Incomplete(CanonicalWorkspaceUsageGraphProjection),
    Cancelled,
}

struct CanonicalWorkspaceUsageGraphAccumulator {
    nodes: Vec<WorkspaceUsageNode>,
    indices_by_id: HashMap<DeclarationId, usize>,
    declaration_spans_by_node: Vec<Vec<(ProjectFile, Range)>>,
    generation: u64,
    selected_ecosystems: BTreeSet<UsageEcosystem>,
    site_file_ids: HashMap<ProjectFile, usize>,
    site_files: Vec<ProjectFile>,
    proven_callsites: HashSet<(usize, usize, usize)>,
    unproven_sites: HashSet<(usize, usize, usize)>,
    /// The names this build's unresolved forward bindings spell, or `None`
    /// when one of them has no identifier this route could read. Bounded by
    /// the workspace's distinct identifiers and discarded with the graph.
    unresolved_names: Option<BTreeSet<String>>,
    strongest_kind_by_line: HashMap<(usize, usize, usize, usize), UsageReferenceKind>,
    kind_projection_complete: bool,
    admitted_callers: HashSet<ProjectFile>,
}

impl CanonicalWorkspaceUsageGraphAccumulator {
    fn new(
        catalog: CanonicalWorkspaceUsageCatalog,
        selected_ecosystems: BTreeSet<UsageEcosystem>,
        admitted_callers: HashSet<ProjectFile>,
    ) -> Self {
        let CanonicalWorkspaceUsageCatalog {
            catalog,
            declaration_spans_by_node,
            generation,
        } = catalog;
        let WorkspaceUsageCatalog {
            nodes,
            indices_by_id,
        } = catalog;
        assert_eq!(
            declaration_spans_by_node.len(),
            nodes.len(),
            "canonical declaration span inventories align one-to-one with graph nodes"
        );
        Self {
            admitted_callers,
            nodes,
            indices_by_id,
            declaration_spans_by_node,
            generation,
            selected_ecosystems,
            site_file_ids: HashMap::default(),
            site_files: Vec::new(),
            proven_callsites: HashSet::default(),
            unproven_sites: HashSet::default(),
            unresolved_names: Some(BTreeSet::new()),
            strongest_kind_by_line: HashMap::default(),
            kind_projection_complete: true,
        }
    }

    const fn generation(&self) -> u64 {
        self.generation
    }

    fn site_file_id(&mut self, file: &ProjectFile) -> usize {
        if let Some(id) = self.site_file_ids.get(file).copied() {
            return id;
        }
        let id = self.site_files.len();
        self.site_files.push(file.clone());
        let previous = self.site_file_ids.insert(file.clone(), id);
        assert!(previous.is_none(), "a site file receives one compact ID");
        id
    }

    /// Stage one provisional fragment batch without retaining its row slice.
    ///
    /// `false` means cancellation interrupted the fold. The partially updated
    /// accumulator remains private and must be discarded by the operation
    /// coordinator rather than finalized or published.
    fn stage_rows(&mut self, rows: &[ReferenceEdgeRow], cancellation: &CancellationToken) -> bool {
        for row in rows {
            if cancellation.is_cancelled() {
                return false;
            }
            assert!(
                self.admitted_callers.contains(&row.site.file),
                "canonical graph rows must belong to explicitly admitted caller files"
            );
            assert_eq!(
                row.generation, self.generation,
                "canonical workspace graph row generation must match its catalog generation"
            );
            assert_eq!(
                row.provenance,
                EdgeProvenance::Forward,
                "forward completeness cannot qualify a non-forward reference row"
            );

            if !is_graph_declaration(&row.target) {
                continue;
            }
            let target_id = row.target_id();
            let target = self
                .indices_by_id
                .get(&target_id)
                .copied()
                .unwrap_or_else(|| {
                    panic!(
                        "canonical reference-edge target {target_id} is absent from the workspace usage catalog"
                    )
                });
            let source = row.site.enclosing.as_ref().and_then(|enclosing| {
                if !is_graph_declaration(enclosing) {
                    return None;
                }
                let source_id = enclosing.declaration_id();
                Some(
                    self.indices_by_id
                        .get(&source_id)
                        .copied()
                        .unwrap_or_else(|| {
                            panic!(
                                "canonical reference-edge source {source_id} is absent from the workspace usage catalog"
                            )
                        }),
                )
            });
            if !self
                .selected_ecosystems
                .contains(&self.nodes[target].key.ecosystem)
            {
                continue;
            }
            if row.site.enclosing.is_none() || source == Some(target) {
                continue;
            }

            let external_usage = row.included_in(UsageHitSurface::ExternalUsages);
            let unproven_self_receiver =
                row.proof == UsageProof::Unproven && row.usage_kind == UsageHitKind::SelfReceiver;
            if !external_usage && !unproven_self_receiver {
                continue;
            }

            let mut site_file = None;
            if row.proof == UsageProof::Proven {
                // Preserve the legacy cap boundary: a proven external target
                // site counts before definition-overlap and caller-node
                // exclusions.
                let file = self.site_file_id(&row.site.file);
                self.proven_callsites
                    .insert((target, file, row.site.range.start_byte));
                site_file = Some(file);
            }

            let target_definition_spans = &self.declaration_spans_by_node[target];
            let overlaps_definition = if external_usage {
                !row.included_in_external_usage_graph(target_definition_spans)
            } else {
                row.overlaps_target_definition_spans(target_definition_spans)
            };
            if overlaps_definition {
                continue;
            }
            if row.proof == UsageProof::Unproven {
                let file = self.site_file_id(&row.site.file);
                self.unproven_sites
                    .insert((target, file, row.site.range.start_byte));
                continue;
            }

            let Some(source) = source else {
                continue;
            };
            if self.nodes[source].key.ecosystem != self.nodes[target].key.ecosystem
                || !self
                    .selected_ecosystems
                    .contains(&self.nodes[source].key.ecosystem)
            {
                continue;
            }
            let (kind, kind_is_exact) = usage_reference_kind(row.reference_kind);
            self.kind_projection_complete &= kind_is_exact;
            let file = site_file.expect("every proven row records its target callsite first");
            self.strongest_kind_by_line
                .entry((source, target, file, row.site.range.start_line))
                .and_modify(|strongest| *strongest = (*strongest).max(kind))
                .or_insert(kind);
        }
        !cancellation.is_cancelled()
    }

    #[cfg(any(test, feature = "test-support"))]
    fn finish_with_status_projection(
        self,
        status: &FactReferenceEdgeDomainStatus<'_>,
        cancellation: &CancellationToken,
    ) -> CanonicalWorkspaceUsageGraphProjectionOutcome {
        assert_eq!(
            status.domain(),
            FactReferenceEdgeDeclarationDomain::TypeOrCallable,
            "workspace usage ranking requires type-or-callable edge completeness"
        );
        self.finish_projection(status.generation(), status.completeness(), cancellation)
    }

    #[cfg(test)]
    fn finish(
        self,
        status_generation: u64,
        forward_completeness: &EdgeCompleteness,
        cancellation: &CancellationToken,
    ) -> CanonicalWorkspaceUsageGraphBuildOutcome {
        match self.finish_projection(status_generation, forward_completeness, cancellation) {
            CanonicalWorkspaceUsageGraphProjectionOutcome::Complete(projection) => {
                let Some(graph) = projection.into_workspace_graph(cancellation) else {
                    return CanonicalWorkspaceUsageGraphBuildOutcome::Cancelled;
                };
                CanonicalWorkspaceUsageGraphBuildOutcome::Complete(graph)
            }
            CanonicalWorkspaceUsageGraphProjectionOutcome::Incomplete(projection) => {
                let Some(graph) = projection.into_workspace_graph(cancellation) else {
                    return CanonicalWorkspaceUsageGraphBuildOutcome::Cancelled;
                };
                CanonicalWorkspaceUsageGraphBuildOutcome::Incomplete(graph)
            }
            CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                CanonicalWorkspaceUsageGraphBuildOutcome::Cancelled
            }
        }
    }

    fn finish_projection(
        mut self,
        status_generation: u64,
        forward_completeness: &EdgeCompleteness,
        cancellation: &CancellationToken,
    ) -> CanonicalWorkspaceUsageGraphProjectionOutcome {
        let upstream_cancelled = matches!(
            forward_completeness,
            EdgeCompleteness::Incomplete { reasons }
                if reasons.contains(&EdgeIncompleteReason::Cancelled)
        );
        if upstream_cancelled || cancellation.is_cancelled() {
            return CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled;
        }
        assert_eq!(
            status_generation, self.generation,
            "canonical workspace graph status generation must match its catalog generation"
        );

        let mut proven_inbound = vec![0_usize; self.nodes.len()];
        for (target, _, _) in self.proven_callsites {
            if cancellation.is_cancelled() {
                return CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled;
            }
            proven_inbound[target] = proven_inbound[target].saturating_add(1);
        }
        for (target, _, _) in self.unproven_sites {
            if cancellation.is_cancelled() {
                return CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled;
            }
            self.nodes[target].unproven_inbound =
                self.nodes[target].unproven_inbound.saturating_add(1);
        }
        for (target, total) in proven_inbound.iter().copied().enumerate() {
            if cancellation.is_cancelled() {
                return CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled;
            }
            if total > MAX_CALLSITES {
                self.nodes[target].truncated_inbound = Some(total);
            }
        }

        let mut projected_by_edge = CanonicalProjectedEdgesByNodePair::new();
        for ((source, target, file, line), kind) in self.strongest_kind_by_line {
            if cancellation.is_cancelled() {
                return CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled;
            }
            let (counts, sites) = projected_by_edge
                .entry((source, target))
                .or_insert_with(|| (UsageReferenceCounts::default(), BTreeSet::new()));
            counts.record(kind);
            sites.insert((self.site_files[file].clone(), line));
        }
        let mut edges = Vec::with_capacity(projected_by_edge.len());
        for ((from, to), (counts, sites)) in projected_by_edge {
            if cancellation.is_cancelled() {
                return CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled;
            }
            let mut ordered_sites = Vec::with_capacity(sites.len());
            for site in sites {
                if cancellation.is_cancelled() {
                    return CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled;
                }
                ordered_sites.push(site);
            }
            edges.push(CanonicalWorkspaceUsageProjectedEdge {
                from,
                to,
                counts,
                sites: ordered_sites,
            });
        }

        #[cfg(test)]
        let resolved_ecosystems = {
            let mut resolved = BTreeSet::new();
            for node in &self.nodes {
                if cancellation.is_cancelled() {
                    return CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled;
                }
                if self.selected_ecosystems.contains(&node.key.ecosystem) {
                    resolved.insert(node.key.ecosystem);
                }
            }
            resolved.into_iter().collect()
        };
        let projection = CanonicalWorkspaceUsageGraphProjection {
            nodes: self.nodes,
            edges,
            raw_proven_inbound: proven_inbound,
            admitted_callers: self.admitted_callers,
            unresolved_names: self.unresolved_names,
            forward_completeness: forward_completeness.clone(),
            kind_projection_complete: self.kind_projection_complete,
            #[cfg(test)]
            resolved_ecosystems,
        };
        if cancellation.is_cancelled() {
            return CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled;
        }
        let upstream_complete = [
            EdgeAxis::ForwardProjection,
            EdgeAxis::OwnerClassification,
            EdgeAxis::KindClassification,
        ]
        .into_iter()
        .all(|axis| forward_completeness.covers(axis));
        if upstream_complete && self.kind_projection_complete {
            CanonicalWorkspaceUsageGraphProjectionOutcome::Complete(projection)
        } else {
            CanonicalWorkspaceUsageGraphProjectionOutcome::Incomplete(projection)
        }
    }
}

/// Site-preserving result of one selected-Java canonical workspace reduction.
///
/// This remains crate-private. The public test-support facade converts it to
/// the incumbent [`crate::searchtools::UsageGraphResult`], while the ranking
/// adapter consumes the same nodes and edges without the site inventory.
pub(crate) struct SelectedWorkspaceUsageGraphProjection {
    pub(crate) nodes: Vec<WorkspaceUsageNode>,
    pub(crate) edges: Vec<CanonicalWorkspaceUsageProjectedEdge>,
    /// Exact distinct (target, source file, byte offset) counts, including
    /// below-cap totals. Aligned with nodes, never inferred from line sites.
    pub(crate) raw_proven_inbound: Vec<usize>,
    /// Includes admitted empty files. Dependency declaration files are not
    /// callers unless the source operation independently admitted them.
    pub(crate) admitted_callers: HashSet<ProjectFile>,
    /// The names this build's unresolved forward bindings spell, or `None`
    /// when one of them has no identifier the route could read.
    ///
    /// A forward-resolution gap can only add an inbound edge, never remove
    /// one, and only to a declaration one of these names reaches. A consumer
    /// that proves a declaration unused abstains on those and keeps its proof
    /// for the rest; `None` leaves it no attribution, and it abstains on the
    /// whole pass.
    pub(crate) unresolved_names: Option<BTreeSet<String>>,
    pub(crate) forward_completeness: EdgeCompleteness,
    pub(crate) kind_projection_complete: bool,
    pub(crate) generation: u64,
    pub(crate) reference_count: usize,
    pub(crate) projected_edge_count: usize,
    pub(crate) batch_count: usize,
    pub(crate) root_binding_metrics: ResolutionBatchMetrics,
    #[cfg(test)]
    pub(crate) resolved_ecosystems: Vec<UsageEcosystem>,
}

impl SelectedWorkspaceUsageGraphProjection {
    pub(crate) fn raw_proven_inbound(&self) -> &[usize] {
        &self.raw_proven_inbound
    }

    pub(crate) fn admitted_callers(&self) -> &HashSet<ProjectFile> {
        &self.admitted_callers
    }

    #[cfg(any(test, feature = "test-support"))]
    fn into_ranking_parts(
        self,
        cancellation: &CancellationToken,
    ) -> Option<(WorkspaceUsageGraph, u64, usize, usize, usize)> {
        assert_eq!(self.raw_proven_inbound().len(), self.nodes.len());
        let edges = projected_edges_into_ranking_edges(&self.nodes, self.edges, cancellation)?;
        let graph = WorkspaceUsageGraph {
            nodes: self.nodes,
            edges,
            #[cfg(test)]
            resolved_ecosystems: self.resolved_ecosystems,
        };
        Some((
            graph,
            self.generation,
            self.reference_count,
            self.projected_edge_count,
            self.batch_count,
        ))
    }
}

/// Atomic selected-Java projection result before consumer-specific rendering.
pub(crate) enum SelectedWorkspaceUsageGraphProjectionOutcome {
    Complete(SelectedWorkspaceUsageGraphProjection),
    Incomplete(SelectedWorkspaceUsageGraphProjection),
    Cancelled,
    Stale,
    Unavailable(String),
}

/// Identity metadata for one node in the union of selected projections.
///
/// Deliberately excludes inbound counters: this is a declaration descriptor,
/// not a node in a graph with merged coverage. Original node metadata remains
/// available through the initial catalog and each borrowed contribution.
pub(crate) struct CanonicalWorkspaceUsageDeclaration<'a> {
    pub(crate) key: &'a WorkspaceUsageNodeKey,
    pub(crate) primary: &'a CodeUnit,
    pub(crate) primary_range: Option<Range>,
}

/// One contribution with its original evidence and a new endpoint numbering.
pub(crate) struct CanonicalWorkspaceUsageRemappedProjection<'a> {
    pub(crate) projection: &'a SelectedWorkspaceUsageGraphProjection,
    pub(crate) node_indices: Vec<usize>,
}

pub(crate) struct CanonicalWorkspaceUsageRemappedEdge<'a> {
    pub(crate) from: usize,
    pub(crate) to: usize,
    pub(crate) counts: UsageReferenceCounts,
    pub(crate) sites: &'a [(ProjectFile, usize)],
}

impl CanonicalWorkspaceUsageRemappedProjection<'_> {
    pub(crate) fn edges(&self) -> impl Iterator<Item = CanonicalWorkspaceUsageRemappedEdge<'_>> {
        self.projection
            .edges
            .iter()
            .map(|edge| CanonicalWorkspaceUsageRemappedEdge {
                from: self.node_indices[edge.from],
                to: self.node_indices[edge.to],
                counts: edge.counts,
                sites: &edge.sites,
            })
    }
}

/// An identity union, not an aggregated usage graph.
///
/// Contributions remain separate even if their caller files overlap. Counts,
/// line sites, inbound uncertainty, completeness, and telemetry are never
/// summed or deduplicated here. Consumers must retain admission ownership when
/// later combining evidence from disjoint caller-file contributions.
///
/// Raw proven inbound counts are retained separately from collapsed line
/// sites. Only the disjoint-admission reducer may sum those counts; this
/// identity primitive also accepts overlapping contributions without merging
/// or claiming complete graph evidence for them.
pub(crate) struct CanonicalWorkspaceUsageNodeRemapping<'a> {
    pub(crate) generation: u64,
    pub(crate) declarations: Vec<CanonicalWorkspaceUsageDeclaration<'a>>,
    pub(crate) initial_nodes: &'a [WorkspaceUsageNode],
    pub(crate) initial_node_indices: Vec<usize>,
    pub(crate) projections: Vec<CanonicalWorkspaceUsageRemappedProjection<'a>>,
}

pub(crate) enum CanonicalWorkspaceUsageNodeRemappingOutcome<'a> {
    Ready(CanonicalWorkspaceUsageNodeRemapping<'a>),
    Cancelled,
    Stale { expected: u64, actual: u64 },
}

/// Share exact DeclarationId endpoint numbering without projecting through
/// names or dropping dependency declarations absent from the initial catalog.
/// All inputs are borrowed and all index tables remain private until success.
/// The caller supplies the initial catalog's generation even when it is empty;
/// operation authority must still be revalidated before publishing a graph.
pub(crate) fn remap_workspace_usage_projection_nodes<'a>(
    initial_nodes: &'a [WorkspaceUsageNode],
    initial_generation: u64,
    projections: &'a [SelectedWorkspaceUsageGraphProjection],
    expected_generation: u64,
    cancellation: &CancellationToken,
) -> CanonicalWorkspaceUsageNodeRemappingOutcome<'a> {
    if cancellation.is_cancelled() {
        return CanonicalWorkspaceUsageNodeRemappingOutcome::Cancelled;
    }
    if initial_generation != expected_generation {
        return CanonicalWorkspaceUsageNodeRemappingOutcome::Stale {
            expected: expected_generation,
            actual: initial_generation,
        };
    }
    for projection in projections {
        if cancellation.is_cancelled() {
            return CanonicalWorkspaceUsageNodeRemappingOutcome::Cancelled;
        }
        if projection.generation != expected_generation {
            return CanonicalWorkspaceUsageNodeRemappingOutcome::Stale {
                expected: expected_generation,
                actual: projection.generation,
            };
        }
    }
    let mut by_id = HashMap::default();
    for node in initial_nodes
        .iter()
        .chain(projections.iter().flat_map(|projection| &projection.nodes))
    {
        if cancellation.is_cancelled() {
            return CanonicalWorkspaceUsageNodeRemappingOutcome::Cancelled;
        }
        let descriptor =
            by_id
                .entry(&node.key.id)
                .or_insert_with(|| CanonicalWorkspaceUsageDeclaration {
                    key: &node.key,
                    primary: &node.primary,
                    primary_range: node.primary_range,
                });
        assert_eq!(
            descriptor.key, &node.key,
            "one DeclarationId must retain compatible graph identity metadata"
        );
        assert_eq!(
            descriptor.primary, &node.primary,
            "one DeclarationId must retain its exact declaration"
        );
        // The complete span breaks equal-start ties so contribution order
        // cannot change the retained dependency declaration metadata.
        descriptor.primary_range = match (descriptor.primary_range, node.primary_range) {
            (Some(left), Some(right)) => Some(
                [left, right]
                    .into_iter()
                    .min_by_key(|range| (range_key(range), range.end_byte, range.end_line))
                    .expect("two primary ranges always have a minimum"),
            ),
            (left, right) => left.or(right),
        };
    }
    let mut declarations = by_id.into_values().collect::<Vec<_>>();
    declarations.sort_by(|left, right| left.key.id.cmp(&right.key.id));
    let mut indices = HashMap::default();
    for (index, declaration) in declarations.iter().enumerate() {
        if cancellation.is_cancelled() {
            return CanonicalWorkspaceUsageNodeRemappingOutcome::Cancelled;
        }
        indices.insert(&declaration.key.id, index);
    }
    let mut initial_node_indices = Vec::with_capacity(initial_nodes.len());
    for node in initial_nodes {
        if cancellation.is_cancelled() {
            return CanonicalWorkspaceUsageNodeRemappingOutcome::Cancelled;
        }
        initial_node_indices.push(indices[&node.key.id]);
    }
    let mut remapped = Vec::with_capacity(projections.len());
    for projection in projections {
        let mut node_indices = Vec::with_capacity(projection.nodes.len());
        for node in &projection.nodes {
            if cancellation.is_cancelled() {
                return CanonicalWorkspaceUsageNodeRemappingOutcome::Cancelled;
            }
            node_indices.push(indices[&node.key.id]);
        }
        for edge in &projection.edges {
            if cancellation.is_cancelled() {
                return CanonicalWorkspaceUsageNodeRemappingOutcome::Cancelled;
            }
            assert!(
                edge.from < node_indices.len() && edge.to < node_indices.len(),
                "a canonical edge must name existing projection nodes"
            );
        }
        remapped.push(CanonicalWorkspaceUsageRemappedProjection {
            projection,
            node_indices,
        });
    }
    if cancellation.is_cancelled() {
        return CanonicalWorkspaceUsageNodeRemappingOutcome::Cancelled;
    }
    CanonicalWorkspaceUsageNodeRemappingOutcome::Ready(CanonicalWorkspaceUsageNodeRemapping {
        generation: expected_generation,
        declarations,
        initial_nodes,
        initial_node_indices,
        projections: remapped,
    })
}

/// Reduce contributions owning disjoint, exact caller-file inventories.
///
/// A projection has already collapsed kinds per (caller, target, file, line).
/// Disjoint file admission makes those keys and raw byte-site counts disjoint
/// too. Overlapping admission, including an empty file, is an error: without
/// reference identities these aggregates cannot be losslessly deduplicated.
/// Telemetry describes the sum of actual contributing work, not the work that
/// a hypothetical joint producer would have performed. No prefix is published
/// on cancellation, a stale generation, or invalid ownership.
pub(crate) fn aggregate_disjoint_workspace_usage_projections(
    projections: &[SelectedWorkspaceUsageGraphProjection],
    expected_generation: u64,
    cancellation: &CancellationToken,
) -> StoreResult<SelectedWorkspaceUsageGraphProjectionOutcome> {
    let remapping = match remap_workspace_usage_projection_nodes(
        &[],
        expected_generation,
        projections,
        expected_generation,
        cancellation,
    ) {
        CanonicalWorkspaceUsageNodeRemappingOutcome::Ready(remapping) => remapping,
        CanonicalWorkspaceUsageNodeRemappingOutcome::Cancelled => {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        }
        CanonicalWorkspaceUsageNodeRemappingOutcome::Stale { expected, actual } => {
            debug_assert_ne!(expected, actual);
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale);
        }
    };
    let mut admitted_callers = HashSet::default();
    let mut overlapping = BTreeSet::new();
    let mut unresolved_names = Some(BTreeSet::new());
    for projection in projections {
        for file in projection.admitted_callers() {
            if cancellation.is_cancelled() {
                return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
            }
            if !admitted_callers.insert(file.clone()) {
                overlapping.insert(file.clone());
            }
        }
        // Caller admission is disjoint, but a declaration one contribution's
        // unresolved binding can reach may be declared in another's files.
        // The union is the aggregate's evidence, and one contribution that
        // could not name its unresolved references leaves the aggregate with
        // no attribution at all.
        match (&mut unresolved_names, &projection.unresolved_names) {
            (Some(union), Some(names)) => {
                for name in names {
                    if cancellation.is_cancelled() {
                        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
                    }
                    union.insert(name.clone());
                }
            }
            (slot, None) => *slot = None,
            (None, Some(_)) => {}
        }
    }
    if !overlapping.is_empty() {
        return Err(StoreError::new(format!(
            "canonical usage contributions have overlapping admitted caller files: {overlapping:?}"
        )));
    }

    let mut nodes = Vec::with_capacity(remapping.declarations.len());
    for declaration in &remapping.declarations {
        if cancellation.is_cancelled() {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        }
        nodes.push(WorkspaceUsageNode {
            key: declaration.key.clone(),
            primary: declaration.primary.clone(),
            primary_range: declaration.primary_range,
            declaration_files: Vec::new(),
            declaration_ids: Vec::new(),
            truncated_inbound: None,
            unproven_inbound: 0,
        });
    }
    let mut raw_proven_inbound = vec![0_usize; nodes.len()];
    let mut projected_by_edge = CanonicalProjectedEdgesByNodePair::new();
    let mut reasons = Vec::new();
    let mut kind_projection_complete = true;
    let mut reference_count = 0_usize;
    let mut projected_edge_count = 0_usize;
    let mut batch_count = 0_usize;
    let mut root_binding_metrics = ResolutionBatchMetrics::default();
    #[cfg(test)]
    let mut resolved_ecosystems = BTreeSet::new();
    for contribution in &remapping.projections {
        if cancellation.is_cancelled() {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        }
        let projection = contribution.projection;
        assert_eq!(
            projection.raw_proven_inbound().len(),
            projection.nodes.len()
        );
        if let EdgeCompleteness::Incomplete { reasons: incoming } = &projection.forward_completeness
        {
            for reason in incoming {
                if cancellation.is_cancelled() || reason == &EdgeIncompleteReason::Cancelled {
                    return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
                }
                if !reasons.contains(reason) {
                    reasons.push(reason.clone());
                }
            }
        }
        kind_projection_complete &= projection.kind_projection_complete;
        reference_count = reference_count
            .checked_add(projection.reference_count)
            .expect("reference count overflow");
        projected_edge_count = projected_edge_count
            .checked_add(projection.projected_edge_count)
            .expect("projected edge count overflow");
        batch_count = batch_count
            .checked_add(projection.batch_count)
            .expect("batch count overflow");
        root_binding_metrics.accumulate(projection.root_binding_metrics);
        #[cfg(test)]
        resolved_ecosystems.extend(projection.resolved_ecosystems.iter().copied());
        for (local, &global) in contribution.node_indices.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
            }
            let source = &projection.nodes[local];
            raw_proven_inbound[global] = raw_proven_inbound[global]
                .checked_add(projection.raw_proven_inbound()[local])
                .expect("raw inbound count overflow");
            let node = &mut nodes[global];
            node.unproven_inbound = node
                .unproven_inbound
                .checked_add(source.unproven_inbound)
                .expect("unproven inbound count overflow");
            for file in &source.declaration_files {
                if cancellation.is_cancelled() {
                    return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
                }
                node.declaration_files.push(file.clone());
            }
            for id in &source.declaration_ids {
                if cancellation.is_cancelled() {
                    return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
                }
                node.declaration_ids.push(id.clone());
            }
        }
        for edge in contribution.edges() {
            if cancellation.is_cancelled() {
                return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
            }
            let (counts, sites) = projected_by_edge.entry((edge.from, edge.to)).or_default();
            counts.calls = counts.calls.saturating_add(edge.counts.calls);
            counts.members = counts.members.saturating_add(edge.counts.members);
            counts.types = counts.types.saturating_add(edge.counts.types);
            counts.other = counts.other.saturating_add(edge.counts.other);
            for site in edge.sites {
                if cancellation.is_cancelled() {
                    return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
                }
                assert!(
                    projection.admitted_callers().contains(&site.0),
                    "projected edge site must belong to its contribution's caller admission"
                );
                assert!(
                    sites.insert(site.clone()),
                    "disjoint caller contributions cannot duplicate a projected edge site"
                );
            }
        }
    }
    for (node, &raw_count) in nodes.iter_mut().zip(&raw_proven_inbound) {
        if cancellation.is_cancelled() {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        }
        node.declaration_files.sort();
        node.declaration_files.dedup();
        node.declaration_ids.sort();
        node.declaration_ids.dedup();
        node.truncated_inbound = (raw_count > MAX_CALLSITES).then_some(raw_count);
    }
    let mut edges = Vec::with_capacity(projected_by_edge.len());
    for ((from, to), (counts, sites)) in projected_by_edge {
        let mut ordered_sites = Vec::with_capacity(sites.len());
        for site in sites {
            if cancellation.is_cancelled() {
                return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
            }
            ordered_sites.push(site);
        }
        edges.push(CanonicalWorkspaceUsageProjectedEdge {
            from,
            to,
            counts,
            sites: ordered_sites,
        });
    }
    let forward_completeness = if reasons.is_empty() {
        EdgeCompleteness::Complete
    } else {
        EdgeCompleteness::Incomplete { reasons }
    };
    let complete = kind_projection_complete
        && [
            EdgeAxis::ForwardProjection,
            EdgeAxis::OwnerClassification,
            EdgeAxis::KindClassification,
        ]
        .into_iter()
        .all(|axis| forward_completeness.covers(axis));
    let projection = SelectedWorkspaceUsageGraphProjection {
        nodes,
        edges,
        raw_proven_inbound,
        admitted_callers,
        unresolved_names,
        forward_completeness,
        kind_projection_complete,
        generation: expected_generation,
        reference_count,
        projected_edge_count,
        batch_count,
        root_binding_metrics,
        #[cfg(test)]
        resolved_ecosystems: resolved_ecosystems.into_iter().collect(),
    };
    if cancellation.is_cancelled() {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
    }
    Ok(if complete {
        SelectedWorkspaceUsageGraphProjectionOutcome::Complete(projection)
    } else {
        SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(projection)
    })
}

/// Merge native contributions into an incumbent graph without interpreting
/// either provider's endpoints through display names.
pub(super) fn merge_workspace_usage_graph_projections(
    initial: WorkspaceUsageGraph,
    projections: &[SelectedWorkspaceUsageGraphProjection],
    generation: u64,
    cancellation: &CancellationToken,
) -> WorkspaceUsageGraphBuildOutcome {
    if cancellation.is_cancelled() {
        return WorkspaceUsageGraphBuildOutcome::Cancelled;
    }
    // Avoid rebuilding the complete catalog when every registered backend
    // still uses the incumbent graph representation.
    if projections.is_empty() {
        return WorkspaceUsageGraphBuildOutcome::Complete(initial);
    }
    let (complete, projection) =
        match aggregate_disjoint_workspace_usage_projections(projections, generation, cancellation)
        {
            Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Complete(projection)) => {
                (true, projection)
            }
            Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(projection)) => {
                (false, projection)
            }
            Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled) => {
                return WorkspaceUsageGraphBuildOutcome::Cancelled;
            }
            Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale) => {
                return WorkspaceUsageGraphBuildOutcome::Stale;
            }
            Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason)) => {
                return WorkspaceUsageGraphBuildOutcome::Unavailable(reason);
            }
            Err(error) => return WorkspaceUsageGraphBuildOutcome::Failed(error),
        };
    let remapping = match remap_workspace_usage_projection_nodes(
        &initial.nodes,
        generation,
        std::slice::from_ref(&projection),
        generation,
        cancellation,
    ) {
        CanonicalWorkspaceUsageNodeRemappingOutcome::Ready(remapping) => remapping,
        CanonicalWorkspaceUsageNodeRemappingOutcome::Cancelled => {
            return WorkspaceUsageGraphBuildOutcome::Cancelled;
        }
        CanonicalWorkspaceUsageNodeRemappingOutcome::Stale { expected, actual } => {
            debug_assert_ne!(expected, actual);
            return WorkspaceUsageGraphBuildOutcome::Stale;
        }
    };
    assert_eq!(remapping.generation, generation);
    let mut nodes = Vec::with_capacity(remapping.declarations.len());
    for declaration in &remapping.declarations {
        if cancellation.is_cancelled() {
            return WorkspaceUsageGraphBuildOutcome::Cancelled;
        }
        nodes.push(WorkspaceUsageNode {
            key: declaration.key.clone(),
            primary: declaration.primary.clone(),
            primary_range: declaration.primary_range,
            declaration_files: Vec::new(),
            declaration_ids: Vec::new(),
            truncated_inbound: None,
            unproven_inbound: 0,
        });
    }
    let contribution = &remapping.projections[0];
    for (source, &index) in remapping
        .initial_nodes
        .iter()
        .zip(&remapping.initial_node_indices)
        .chain(projection.nodes.iter().zip(&contribution.node_indices))
    {
        if cancellation.is_cancelled() {
            return WorkspaceUsageGraphBuildOutcome::Cancelled;
        }
        let node = &mut nodes[index];
        node.declaration_files
            .extend(source.declaration_files.iter().cloned());
        node.declaration_ids
            .extend(source.declaration_ids.iter().cloned());
        node.truncated_inbound = node.truncated_inbound.max(source.truncated_inbound);
        node.unproven_inbound = node
            .unproven_inbound
            .checked_add(source.unproven_inbound)
            .expect("combined graph inbound uncertainty fits usize");
    }
    for node in &mut nodes {
        if cancellation.is_cancelled() {
            return WorkspaceUsageGraphBuildOutcome::Cancelled;
        }
        node.declaration_files.sort();
        node.declaration_files.dedup();
        node.declaration_ids.sort();
        node.declaration_ids.dedup();
    }
    let mut edges = Vec::with_capacity(initial.edges.len() + projection.edges.len());
    for edge in &initial.edges {
        if cancellation.is_cancelled() {
            return WorkspaceUsageGraphBuildOutcome::Cancelled;
        }
        edges.push(WorkspaceUsageEdge {
            from: remapping.initial_node_indices[edge.from],
            to: remapping.initial_node_indices[edge.to],
            counts: edge.counts,
        });
    }
    for edge in contribution.edges() {
        if cancellation.is_cancelled() {
            return WorkspaceUsageGraphBuildOutcome::Cancelled;
        }
        if nodes[edge.to].truncated_inbound.is_none() {
            edges.push(WorkspaceUsageEdge {
                from: edge.from,
                to: edge.to,
                counts: edge.counts,
            });
        }
    }
    edges.sort_by_key(|edge| (edge.from, edge.to));
    #[cfg(test)]
    let resolved_ecosystems = initial
        .resolved_ecosystems
        .iter()
        .chain(&projection.resolved_ecosystems)
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let graph = WorkspaceUsageGraph {
        nodes,
        edges,
        #[cfg(test)]
        resolved_ecosystems,
    };
    if cancellation.is_cancelled() {
        return WorkspaceUsageGraphBuildOutcome::Cancelled;
    }
    if complete {
        WorkspaceUsageGraphBuildOutcome::Complete(graph)
    } else {
        WorkspaceUsageGraphBuildOutcome::Incomplete(graph)
    }
}

/// Native producers supply their admitted source declaration catalogue and
/// canonical rows; the shared reducer owns graph admission and line weights.
///
/// Caller admission is independent of the declaration catalog: dependencies
/// may supply endpoints, and admitted empty files still establish ownership.
pub(crate) struct NativeWorkspaceUsageGraphAccumulator(CanonicalWorkspaceUsageGraphAccumulator);

impl NativeWorkspaceUsageGraphAccumulator {
    pub(crate) fn new(
        declarations: Vec<(CodeUnit, Vec<Range>)>,
        generation: u64,
        ecosystem: UsageEcosystem,
        admitted_callers: &HashSet<ProjectFile>,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let catalog = CanonicalWorkspaceUsageCatalog::from_declarations_with_all_ranges(
            declarations,
            generation,
            cancellation,
        )?;
        let mut admitted = HashSet::default();
        for file in admitted_callers {
            if cancellation.is_cancelled() {
                return None;
            }
            admitted.insert(file.clone());
        }
        Some(Self(CanonicalWorkspaceUsageGraphAccumulator::new(
            catalog,
            BTreeSet::from([ecosystem]),
            admitted,
        )))
    }

    pub(crate) fn stage(
        &mut self,
        rows: &[ReferenceEdgeRow],
        cancellation: &CancellationToken,
    ) -> bool {
        self.0.stage_rows(rows, cancellation)
    }

    /// Record the names this build's unresolved forward bindings spell.
    /// `None` means one of them had no identifier the route could read, and
    /// the projection then offers no per-declaration attribution at all.
    pub(crate) fn note_unresolved_names(
        &mut self,
        names: Option<&BTreeSet<String>>,
        cancellation: &CancellationToken,
    ) -> bool {
        let Some(names) = names else {
            self.0.unresolved_names = None;
            return !cancellation.is_cancelled();
        };
        for name in names {
            if cancellation.is_cancelled() {
                return false;
            }
            if let Some(recorded) = self.0.unresolved_names.as_mut() {
                recorded.insert(name.clone());
            }
        }
        true
    }

    pub(crate) fn finish(
        self,
        completeness: &EdgeCompleteness,
        summary: &crate::analyzer::resolution::FactResolutionBatchSummary,
        projected_edge_count: usize,
        cancellation: &CancellationToken,
    ) -> SelectedWorkspaceUsageGraphProjectionOutcome {
        let generation = self.0.generation();
        let (complete, projection) =
            match self
                .0
                .finish_projection(generation, completeness, cancellation)
            {
                CanonicalWorkspaceUsageGraphProjectionOutcome::Complete(projection) => {
                    (true, projection)
                }
                CanonicalWorkspaceUsageGraphProjectionOutcome::Incomplete(projection) => {
                    (false, projection)
                }
                CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                    return SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled;
                }
            };
        let projection = SelectedWorkspaceUsageGraphProjection {
            nodes: projection.nodes,
            edges: projection.edges,
            raw_proven_inbound: projection.raw_proven_inbound,
            admitted_callers: projection.admitted_callers,
            unresolved_names: projection.unresolved_names,
            forward_completeness: projection.forward_completeness,
            kind_projection_complete: projection.kind_projection_complete,
            generation,
            reference_count: summary.reference_count(),
            projected_edge_count,
            batch_count: summary.batch_count(),
            root_binding_metrics: summary.root_binding_metrics(),
            #[cfg(test)]
            resolved_ecosystems: projection.resolved_ecosystems,
        };
        if complete {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(projection)
        } else {
            SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(projection)
        }
    }
}

/// Opaque exact-identity ranking graph built from one selected Java snapshot.
///
/// This private-harness surface deliberately exposes only stable cardinality
/// and memory metrics. The graph itself remains analyzer-owned so comparable
/// experiments cannot bypass the production ranking semantics.
#[cfg(any(test, feature = "test-support"))]
pub struct SelectedWorkspaceUsageRankingGraph {
    graph: WorkspaceUsageRankingGraph,
    generation: u64,
    reference_count: usize,
    projected_edge_count: usize,
    batch_count: usize,
}

#[cfg(any(test, feature = "test-support"))]
impl SelectedWorkspaceUsageRankingGraph {
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn reference_count(&self) -> usize {
        self.reference_count
    }

    pub const fn projected_edge_count(&self) -> usize {
        self.projected_edge_count
    }

    pub const fn batch_count(&self) -> usize {
        self.batch_count
    }

    pub fn node_count(&self) -> usize {
        self.graph.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edges.len()
    }

    pub fn incomplete_node_count(&self) -> usize {
        self.graph
            .nodes
            .iter()
            .filter(|node| node.incomplete)
            .count()
    }

    pub fn retained_bytes(&self) -> usize {
        self.graph.retained_bytes()
    }

    /// Consume the opaque test-support wrapper at the relevance boundary.
    ///
    /// Keeping this conversion crate-private lets the full relevance adapter
    /// reuse the production cache and calibrated PageRank implementation
    /// without exposing analyzer-owned graph internals to the differential
    /// harness.
    pub(crate) fn into_ranking_graph(self) -> WorkspaceUsageRankingGraph {
        self.graph
    }

    #[cfg(test)]
    pub(crate) fn from_ranking_graph_for_test(
        graph: WorkspaceUsageRankingGraph,
        generation: u64,
    ) -> Self {
        let projected_edge_count = graph.edges.len();
        Self {
            graph,
            generation,
            reference_count: projected_edge_count,
            projected_edge_count,
            batch_count: 1,
        }
    }

    /// Rank files from this retained graph with the incumbent calibrated exact
    /// PageRank operation. No graph build or production cache lookup occurs.
    ///
    /// `None` means cancellation. Semantic graph completeness remains encoded
    /// by [`SelectedWorkspaceUsageRankingBuildOutcome`], so an `Incomplete`
    /// graph can still rank its sound positive evidence without becoming
    /// cacheable.
    pub fn rank_files_with_cancellation(
        &self,
        seeds: &[(ProjectFile, f64)],
        k: usize,
        cancellation: &CancellationToken,
    ) -> Option<Vec<(ProjectFile, f64)>> {
        crate::relevance::rank_exact_workspace_usage_graph_with_cancellation(
            &self.graph,
            seeds,
            k,
            cancellation,
        )
    }
}

/// Atomic selected-Java canonical graph build outcome.
///
/// `Incomplete` contains sound positive evidence but is not cacheable and
/// cannot prove that an absent edge does not exist. `Cancelled`, `Stale`, and
/// `Err` publish no graph or staged prefix.
#[cfg(any(test, feature = "test-support"))]
pub enum SelectedWorkspaceUsageRankingBuildOutcome {
    Complete(SelectedWorkspaceUsageRankingGraph),
    Incomplete(SelectedWorkspaceUsageRankingGraph),
    Cancelled,
    Stale,
    Unavailable(String),
}

#[cfg(any(test, feature = "test-support"))]
fn validate_selected_workspace_coverage<S>(
    analyzer: &dyn IAnalyzer,
    selected: &SelectedFactResolutionSnapshot<'_, S>,
    edge_catalog: &FactReferenceEdgeCatalog<'_>,
    workspace_catalog: &CanonicalWorkspaceUsageCatalog,
    cancellation: &CancellationToken,
) -> StoreResult<Option<(HashSet<BindingFragmentId>, HashSet<ProjectFile>)>>
where
    S: FactResolutionSource,
{
    let coverage =
        validate_selected_reference_edge_coverage(analyzer, selected, edge_catalog, cancellation);
    if cancellation.is_cancelled()
        || analyzer.project().analysis_generation() != edge_catalog.generation()
    {
        return Ok(None);
    }
    let Some(coverage) = coverage? else {
        return Ok(None);
    };

    let mut workspace_jvm_files = HashSet::default();
    for node in workspace_catalog.nodes() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if node.key.ecosystem == UsageEcosystem::Jvm {
            workspace_jvm_files.extend(node.declaration_files.iter().cloned());
        }
    }
    if !workspace_jvm_files.is_subset(coverage.files()) {
        return Err(StoreError::new(format!(
            "selected Java resolution cannot certify a JVM workspace graph containing non-selected declaration files: workspace_jvm={workspace_jvm_files:?}, edge_catalog={:?}",
            coverage.files()
        )));
    }
    let mut admitted_callers = HashSet::default();
    for file in coverage.files() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        admitted_callers.insert(file.clone());
    }
    Ok(Some((coverage.into_fragments(), admitted_callers)))
}

/// Stream one complete selected-Java reference inventory through the shared
/// workspace reducer without retaining a workspace-sized row vector.
///
/// Callback stages are provisional. Cancellation, source/catalog errors, and
/// a generation change discard the accumulator. Semantic incompleteness,
/// including incomplete reference enumeration, returns the sound positive
/// inventory through `Incomplete` instead.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn build_selected_workspace_usage_graph_projection<S>(
    analyzer: &dyn IAnalyzer,
    selected: &SelectedFactResolutionSnapshot<'_, S>,
    edge_catalog: &FactReferenceEdgeCatalog<'_>,
    maximum_batch_size: usize,
    cancellation: &CancellationToken,
) -> StoreResult<SelectedWorkspaceUsageGraphProjectionOutcome>
where
    S: FactResolutionSource,
{
    if cancellation.is_cancelled() {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
    }
    let generation = edge_catalog.generation();
    if analyzer.project().analysis_generation() != generation {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale);
    }
    let Some(workspace_catalog) =
        CanonicalWorkspaceUsageCatalog::build_with_cancellation(analyzer, cancellation)
    else {
        return Ok(if cancellation.is_cancelled() {
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled
        } else {
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale
        });
    };
    if workspace_catalog.generation != generation {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale);
    }
    let coverage = validate_selected_workspace_coverage(
        analyzer,
        selected,
        edge_catalog,
        &workspace_catalog,
        cancellation,
    );
    if cancellation.is_cancelled() {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
    }
    if analyzer.project().analysis_generation() != generation {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale);
    }
    let Some((selected_fragments, admitted_callers)) = coverage? else {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
    };

    let mut accumulator = CanonicalWorkspaceUsageGraphAccumulator::new(
        workspace_catalog,
        BTreeSet::from([UsageEcosystem::Jvm]),
        admitted_callers,
    );
    assert_eq!(accumulator.generation(), generation);
    let mut staging_cancelled = false;
    let summary = stage_selected_reference_edge_batches(
        selected,
        edge_catalog,
        maximum_batch_size,
        cancellation,
        &mut |batch| {
            if batch.generation() != generation {
                return Err(StoreError::new(format!(
                    "selected Java native edge batch generation {} differs from workspace generation {generation}",
                    batch.generation()
                )));
            }
            if !selected_fragments.contains(&batch.fragment()) {
                return Err(StoreError::new(format!(
                    "selected Java native edge batch names fragment outside the accepted catalog: fragment={:?}, selected={selected_fragments:?}",
                    batch.fragment()
                )));
            }
            if !accumulator.stage_rows(batch.edges(), cancellation) {
                staging_cancelled = true;
            }
            Ok(())
        },
    );
    if staging_cancelled || cancellation.is_cancelled() {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
    }
    if analyzer.project().analysis_generation() != generation {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale);
    }
    let summary = summary?;

    let reference_count = summary.reference_count();
    let projected_edge_count = summary.edge_count();
    let batch_count = summary.batch_count();
    let root_binding_metrics = summary.root_binding_metrics();
    let projection_outcome = accumulator.finish_with_status_projection(
        &summary.domain_status(FactReferenceEdgeDeclarationDomain::TypeOrCallable),
        cancellation,
    );
    if analyzer.project().analysis_generation() != generation {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale);
    }
    let (complete, projection) = match projection_outcome {
        CanonicalWorkspaceUsageGraphProjectionOutcome::Complete(projection) => (true, projection),
        CanonicalWorkspaceUsageGraphProjectionOutcome::Incomplete(projection) => {
            (false, projection)
        }
        CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled => {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        }
    };
    let CanonicalWorkspaceUsageGraphProjection {
        nodes,
        edges,
        raw_proven_inbound,
        admitted_callers,
        unresolved_names,
        forward_completeness,
        kind_projection_complete,
        #[cfg(test)]
        resolved_ecosystems,
    } = projection;
    let projection = SelectedWorkspaceUsageGraphProjection {
        nodes,
        edges,
        raw_proven_inbound,
        admitted_callers,
        unresolved_names,
        forward_completeness,
        kind_projection_complete,
        generation,
        reference_count,
        projected_edge_count,
        batch_count,
        root_binding_metrics,
        #[cfg(test)]
        resolved_ecosystems,
    };
    if cancellation.is_cancelled() {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
    }
    if analyzer.project().analysis_generation() != generation {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale);
    }
    let outcome = if complete {
        SelectedWorkspaceUsageGraphProjectionOutcome::Complete(projection)
    } else {
        SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(projection)
    };
    if cancellation.is_cancelled() {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
    }
    if analyzer.project().analysis_generation() != generation {
        return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale);
    }
    Ok(outcome)
}

/// Stream one complete selected-Java reference inventory into an exact
/// workspace ranking graph without retaining a workspace-sized row vector.
#[cfg(any(test, feature = "test-support"))]
pub fn build_selected_workspace_usage_ranking_graph<S>(
    analyzer: &dyn IAnalyzer,
    selected: &SelectedFactResolutionSnapshot<'_, S>,
    edge_catalog: &FactReferenceEdgeCatalog<'_>,
    maximum_batch_size: usize,
    cancellation: &CancellationToken,
) -> StoreResult<SelectedWorkspaceUsageRankingBuildOutcome>
where
    S: FactResolutionSource,
{
    let projection = build_selected_workspace_usage_graph_projection(
        analyzer,
        selected,
        edge_catalog,
        maximum_batch_size,
        cancellation,
    )?;
    Ok(projection.into_ranking_graph(analyzer, cancellation))
}

#[cfg(any(test, feature = "test-support"))]
impl SelectedWorkspaceUsageGraphProjectionOutcome {
    pub(crate) fn into_ranking_graph(
        self,
        analyzer: &dyn IAnalyzer,
        cancellation: &CancellationToken,
    ) -> SelectedWorkspaceUsageRankingBuildOutcome {
        let (complete, projection) = match self {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(projection) => {
                (true, projection)
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(projection) => {
                (false, projection)
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                return SelectedWorkspaceUsageRankingBuildOutcome::Cancelled;
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale => {
                return SelectedWorkspaceUsageRankingBuildOutcome::Stale;
            }
            SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(reason) => {
                return SelectedWorkspaceUsageRankingBuildOutcome::Unavailable(reason);
            }
        };
        let Some((graph, generation, reference_count, projected_edge_count, batch_count)) =
            projection.into_ranking_parts(cancellation)
        else {
            return SelectedWorkspaceUsageRankingBuildOutcome::Cancelled;
        };
        let Some(graph) =
            WorkspaceUsageRankingGraph::from_exact_with_cancellation(graph, cancellation)
        else {
            return SelectedWorkspaceUsageRankingBuildOutcome::Cancelled;
        };
        if cancellation.is_cancelled() {
            return SelectedWorkspaceUsageRankingBuildOutcome::Cancelled;
        }
        if analyzer.project().analysis_generation() != generation {
            return SelectedWorkspaceUsageRankingBuildOutcome::Stale;
        }
        let graph = SelectedWorkspaceUsageRankingGraph {
            graph,
            generation,
            reference_count,
            projected_edge_count,
            batch_count,
        };
        let outcome = if complete {
            SelectedWorkspaceUsageRankingBuildOutcome::Complete(graph)
        } else {
            SelectedWorkspaceUsageRankingBuildOutcome::Incomplete(graph)
        };
        if cancellation.is_cancelled() {
            return SelectedWorkspaceUsageRankingBuildOutcome::Cancelled;
        }
        if analyzer.project().analysis_generation() != generation {
            return SelectedWorkspaceUsageRankingBuildOutcome::Stale;
        }
        outcome
    }
}

#[cfg(test)]
fn reduce_canonical_reference_edge_rows_to_workspace_usage_graph(
    catalog: CanonicalWorkspaceUsageCatalog,
    rows: &[ReferenceEdgeRow],
    status_generation: u64,
    forward_completeness: &EdgeCompleteness,
    selected_ecosystems: &BTreeSet<UsageEcosystem>,
    cancellation: &CancellationToken,
) -> CanonicalWorkspaceUsageGraphBuildOutcome {
    let upstream_cancelled = matches!(
        forward_completeness,
        EdgeCompleteness::Incomplete { reasons }
            if reasons.contains(&EdgeIncompleteReason::Cancelled)
    );
    if upstream_cancelled || cancellation.is_cancelled() {
        return CanonicalWorkspaceUsageGraphBuildOutcome::Cancelled;
    }
    // This test helper's supplied rows are its entire synthetic inventory.
    // Selected production-preparation builders retain admission independently.
    let mut accumulator = CanonicalWorkspaceUsageGraphAccumulator::new(
        catalog,
        selected_ecosystems.clone(),
        rows.iter().map(|row| row.site.file.clone()).collect(),
    );
    if !accumulator.stage_rows(rows, cancellation) {
        return CanonicalWorkspaceUsageGraphBuildOutcome::Cancelled;
    }
    accumulator.finish(status_generation, forward_completeness, cancellation)
}

/// Project canonical kinds into the legacy weight categories.
///
/// `StaticReference` currently says only that the receiver names a type. The
/// row classifier checks that before it distinguishes a call from a member
/// access, so this reducer cannot honestly choose between `Call` and `Member`.
/// Missing kinds have the same limitation. Both contribute `Other` as
/// best-effort positive evidence and make the result ineligible for a complete
/// graph/cache until the row layer publishes the finer distinction.
fn usage_reference_kind(kind: Option<ReferenceKind>) -> (UsageReferenceKind, bool) {
    match kind {
        Some(
            ReferenceKind::MethodCall | ReferenceKind::ConstructorCall | ReferenceKind::SuperCall,
        ) => (UsageReferenceKind::Call, true),
        Some(ReferenceKind::FieldRead | ReferenceKind::FieldWrite) => {
            (UsageReferenceKind::Member, true)
        }
        Some(
            ReferenceKind::TypeReference
            | ReferenceKind::SelfTypeAlias
            | ReferenceKind::Inheritance,
        ) => (UsageReferenceKind::Type, true),
        Some(ReferenceKind::StaticReference) | None => (UsageReferenceKind::Other, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::resolution::{
        FactReferenceEdgeSelectedFragment, PreloadedFactResolutionService,
        SelectedFactResolutionEngine,
    };
    use crate::analyzer::structural::reference_edges::EdgeSite;
    use crate::analyzer::structural::{OwnerRelation, SiteClass};
    use crate::analyzer::{CodeUnitType, JavaAnalyzer, OverlayProject};
    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use brokk_bifrost_core::analyzer::CodeUnitIndex;
    use std::sync::Arc;

    const CANONICAL_GENERATION: u64 = 17;

    fn test_file(path: &str) -> ProjectFile {
        ProjectFile::new(
            std::env::current_dir().expect("the test working directory must be available"),
            path,
        )
    }

    fn test_range(start_byte: usize, end_byte: usize, line: usize) -> Range {
        Range {
            start_byte,
            end_byte,
            start_line: line,
            end_line: line,
        }
    }

    fn test_unit(file: &ProjectFile, kind: CodeUnitType, short_name: &str) -> CodeUnit {
        CodeUnit::new(file.clone(), kind, "fixture", short_name)
    }

    fn canonical_catalog(
        declarations: impl IntoIterator<Item = (CodeUnit, Vec<Range>)>,
    ) -> CanonicalWorkspaceUsageCatalog {
        CanonicalWorkspaceUsageCatalog::from_declarations_with_all_ranges(
            declarations.into_iter().collect(),
            CANONICAL_GENERATION,
            &CancellationToken::default(),
        )
        .expect("an uncancelled canonical catalog must build")
    }

    fn reduce_canonical_reference_edges_to_workspace_usage_graph(
        catalog: CanonicalWorkspaceUsageCatalog,
        rows: &[ReferenceEdgeRow],
        completeness: &EdgeCompleteness,
        selected_ecosystems: &BTreeSet<UsageEcosystem>,
        cancellation: &CancellationToken,
    ) -> CanonicalWorkspaceUsageGraphBuildOutcome {
        reduce_canonical_reference_edge_rows_to_workspace_usage_graph(
            catalog,
            rows,
            CANONICAL_GENERATION,
            completeness,
            selected_ecosystems,
            cancellation,
        )
    }

    fn canonical_row(
        file: &ProjectFile,
        range: Range,
        enclosing: &CodeUnit,
        target: &CodeUnit,
        reference_kind: Option<ReferenceKind>,
        proof: UsageProof,
    ) -> ReferenceEdgeRow {
        ReferenceEdgeRow {
            site: EdgeSite {
                file: file.clone(),
                range,
                ast_id: None,
                enclosing: Some(enclosing.clone()),
            },
            target: target.clone(),
            reference_kind,
            proof,
            usage_kind: UsageHitKind::Reference,
            site_class: SiteClass::UseSite,
            owner_relation: OwnerRelation::External,
            provenance: EdgeProvenance::Forward,
            generation: CANONICAL_GENERATION,
        }
    }

    fn complete_canonical_graph(
        outcome: CanonicalWorkspaceUsageGraphBuildOutcome,
    ) -> WorkspaceUsageGraph {
        match outcome {
            CanonicalWorkspaceUsageGraphBuildOutcome::Complete(graph) => graph,
            CanonicalWorkspaceUsageGraphBuildOutcome::Incomplete(_) => {
                panic!("complete canonical input must produce a complete graph")
            }
            CanonicalWorkspaceUsageGraphBuildOutcome::Cancelled => {
                panic!("an uncancelled canonical reduction must not cancel")
            }
        }
    }

    fn complete_canonical_projection(
        outcome: CanonicalWorkspaceUsageGraphProjectionOutcome,
    ) -> CanonicalWorkspaceUsageGraphProjection {
        match outcome {
            CanonicalWorkspaceUsageGraphProjectionOutcome::Complete(projection) => projection,
            CanonicalWorkspaceUsageGraphProjectionOutcome::Incomplete(_) => {
                panic!("complete canonical input must produce a complete projection")
            }
            CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                panic!("an uncancelled canonical projection must not cancel")
            }
        }
    }

    fn node_index(graph: &WorkspaceUsageGraph, declaration: &CodeUnit) -> usize {
        let id = declaration.declaration_id();
        graph
            .nodes
            .iter()
            .position(|node| node.declaration_ids.contains(&id))
            .unwrap_or_else(|| panic!("missing graph node for {}", declaration.fq_name()))
    }

    type CanonicalGraphSignature = (
        Vec<(DeclarationId, Option<usize>, usize)>,
        Vec<WorkspaceUsageEdge>,
    );

    fn canonical_graph_signature(graph: &WorkspaceUsageGraph) -> CanonicalGraphSignature {
        (
            graph
                .nodes
                .iter()
                .map(|node| {
                    (
                        node.key.id.clone(),
                        node.truncated_inbound,
                        node.unproven_inbound,
                    )
                })
                .collect(),
            graph.edges.clone(),
        )
    }

    fn remapping_projection(
        caller: &CodeUnit,
        target: &CodeUnit,
        kind: UsageReferenceKind,
    ) -> SelectedWorkspaceUsageGraphProjection {
        let catalog = canonical_catalog([
            (caller.clone(), vec![test_range(0, 80, 1)]),
            (target.clone(), vec![test_range(0, 90, 2)]),
        ]);
        let from = catalog.index_for_id(&caller.declaration_id()).unwrap();
        let to = catalog.index_for_id(&target.declaration_id()).unwrap();
        let mut counts = UsageReferenceCounts::default();
        counts.record(kind);
        let mut raw_proven_inbound = vec![0; catalog.catalog.nodes.len()];
        raw_proven_inbound[to] = 1;
        SelectedWorkspaceUsageGraphProjection {
            nodes: catalog.catalog.nodes,
            raw_proven_inbound,
            admitted_callers: HashSet::from_iter([caller.source().clone()]),
            unresolved_names: Some(BTreeSet::new()),
            edges: vec![CanonicalWorkspaceUsageProjectedEdge {
                from,
                to,
                counts,
                sites: vec![(caller.source().clone(), 7)],
            }],
            forward_completeness: EdgeCompleteness::Complete,
            kind_projection_complete: true,
            generation: CANONICAL_GENERATION,
            reference_count: 11,
            projected_edge_count: 9,
            batch_count: 3,
            root_binding_metrics: ResolutionBatchMetrics::default(),
            resolved_ecosystems: vec![UsageEcosystem::Jvm],
        }
    }

    fn ready_node_remapping<'a>(
        initial: &'a [WorkspaceUsageNode],
        projections: &'a [SelectedWorkspaceUsageGraphProjection],
    ) -> CanonicalWorkspaceUsageNodeRemapping<'a> {
        match remap_workspace_usage_projection_nodes(
            initial,
            CANONICAL_GENERATION,
            projections,
            CANONICAL_GENERATION,
            &CancellationToken::default(),
        ) {
            CanonicalWorkspaceUsageNodeRemappingOutcome::Ready(mapping) => mapping,
            _ => panic!("same-generation uncancelled identity union must be ready"),
        }
    }

    fn projected_inventory(
        declarations: impl IntoIterator<Item = CodeUnit>,
        admitted_callers: HashSet<ProjectFile>,
        rows: &[ReferenceEdgeRow],
    ) -> SelectedWorkspaceUsageGraphProjection {
        let catalog = canonical_catalog(
            declarations
                .into_iter()
                .map(|unit| (unit, vec![test_range(0, 80, 1)])),
        );
        let mut accumulator = CanonicalWorkspaceUsageGraphAccumulator::new(
            catalog,
            BTreeSet::from([UsageEcosystem::Jvm]),
            admitted_callers,
        );
        let cancellation = CancellationToken::default();
        assert!(accumulator.stage_rows(rows, &cancellation));
        let projection = complete_canonical_projection(accumulator.finish_projection(
            CANONICAL_GENERATION,
            &EdgeCompleteness::Complete,
            &cancellation,
        ));
        SelectedWorkspaceUsageGraphProjection {
            nodes: projection.nodes,
            edges: projection.edges,
            raw_proven_inbound: projection.raw_proven_inbound,
            admitted_callers: projection.admitted_callers,
            unresolved_names: projection.unresolved_names,
            forward_completeness: projection.forward_completeness,
            kind_projection_complete: projection.kind_projection_complete,
            generation: CANONICAL_GENERATION,
            reference_count: rows.len(),
            projected_edge_count: rows.len(),
            batch_count: 1,
            root_binding_metrics: ResolutionBatchMetrics::default(),
            resolved_ecosystems: projection.resolved_ecosystems,
        }
    }

    fn complete_disjoint_projection(
        projections: &[SelectedWorkspaceUsageGraphProjection],
    ) -> SelectedWorkspaceUsageGraphProjection {
        match aggregate_disjoint_workspace_usage_projections(
            projections,
            CANONICAL_GENERATION,
            &CancellationToken::default(),
        )
        .expect("disjoint source inventories must be accepted")
        {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(projection) => projection,
            _ => panic!("complete disjoint inventories must yield a complete projection"),
        }
    }

    #[test]
    fn disjoint_projection_matches_joint_rows_across_raw_cap_and_same_line_calls() {
        let first_file = test_file("src/First.java");
        let second_file = test_file("src/Second.java");
        let empty_file = test_file("src/Empty.java");
        let first = test_unit(&first_file, CodeUnitType::Function, "First.run");
        let second = test_unit(&second_file, CodeUnitType::Function, "Second.run");
        let target = test_unit(
            &test_file("dep/Target.java"),
            CodeUnitType::Function,
            "Target.run",
        );
        let make_rows = |file: &ProjectFile, caller: &CodeUnit| {
            let mut rows = (0..MAX_CALLSITES / 2 + 1)
                .map(|index| {
                    canonical_row(
                        file,
                        test_range(100 + index * 2, 101 + index * 2, 7),
                        caller,
                        &target,
                        Some(if index == 0 {
                            ReferenceKind::TypeReference
                        } else {
                            ReferenceKind::MethodCall
                        }),
                        UsageProof::Proven,
                    )
                })
                .collect::<Vec<_>>();
            // Repeated raw rows do not increase inbound evidence. An unproven
            // site contributes uncertainty but never a public/ranking edge.
            rows.push(rows[0].clone());
            rows.push(canonical_row(
                file,
                test_range(90, 91, 6),
                caller,
                &target,
                Some(ReferenceKind::MethodCall),
                UsageProof::Unproven,
            ));
            rows
        };
        let first_rows = make_rows(&first_file, &first);
        let second_rows = make_rows(&second_file, &second);
        let contributions = [
            projected_inventory(
                [first.clone(), target.clone()],
                HashSet::from_iter([first_file.clone(), empty_file.clone()]),
                &first_rows,
            ),
            projected_inventory(
                [target.clone(), second.clone()],
                HashSet::from_iter([second_file.clone()]),
                &second_rows,
            ),
        ];
        assert!(contributions.iter().all(|projection| {
            projection
                .nodes
                .iter()
                .all(|node| node.truncated_inbound.is_none())
        }));
        let aggregate = complete_disjoint_projection(&contributions);
        let joint_rows = first_rows
            .into_iter()
            .chain(second_rows)
            .collect::<Vec<_>>();
        let joint = projected_inventory(
            [first, second, target.clone()],
            HashSet::from_iter([first_file, second_file, empty_file]),
            &joint_rows,
        );
        assert_eq!(
            aggregate
                .nodes
                .iter()
                .map(|node| &node.key.id)
                .collect::<Vec<_>>(),
            joint
                .nodes
                .iter()
                .map(|node| &node.key.id)
                .collect::<Vec<_>>()
        );
        assert_eq!(aggregate.edges, joint.edges);
        assert_eq!(aggregate.raw_proven_inbound(), joint.raw_proven_inbound());
        assert_eq!(aggregate.admitted_callers(), joint.admitted_callers());
        assert_eq!(aggregate.forward_completeness, joint.forward_completeness);
        assert_eq!(
            aggregate.kind_projection_complete,
            joint.kind_projection_complete
        );
        assert_eq!(aggregate.reference_count, joint.reference_count);
        assert_eq!(aggregate.projected_edge_count, joint.projected_edge_count);
        assert_eq!(aggregate.batch_count, 2, "retain actual contribution work");
        for (merged, original) in aggregate.nodes.iter().zip(&joint.nodes) {
            assert_eq!(merged.primary, original.primary);
            assert_eq!(merged.primary_range, original.primary_range);
            assert_eq!(merged.declaration_ids, original.declaration_ids);
            assert_eq!(merged.declaration_files, original.declaration_files);
            assert_eq!(merged.truncated_inbound, original.truncated_inbound);
            assert_eq!(merged.unproven_inbound, original.unproven_inbound);
        }
        let target_index = aggregate
            .nodes
            .iter()
            .position(|node| node.key.id == target.declaration_id())
            .unwrap();
        assert_eq!(
            aggregate.raw_proven_inbound()[target_index],
            2 * (MAX_CALLSITES / 2 + 1)
        );
        assert_eq!(aggregate.nodes[target_index].unproven_inbound, 2);
        assert!(aggregate.nodes[target_index].truncated_inbound.is_some());
        assert!(
            aggregate.edges.iter().all(|edge| edge.counts.calls == 1
                && edge.counts.types == 0
                && edge.sites.len() == 1),
            "the strongest kind wins independently in each admitted file line"
        );
        let ranking = projected_edges_into_ranking_edges(
            &aggregate.nodes,
            aggregate.edges.clone(),
            &CancellationToken::default(),
        )
        .unwrap();
        assert!(
            ranking.is_empty(),
            "joint raw byte-site cap suppresses ranking edges"
        );
        let public = crate::searchtools::selected_usage_graph_result(
            aggregate,
            true,
            &CancellationToken::default(),
        )
        .unwrap();
        let joint_public = crate::searchtools::selected_usage_graph_result(
            joint,
            true,
            &CancellationToken::default(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&public.edges).unwrap(),
            serde_json::to_value(&joint_public.edges).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&public.nodes).unwrap(),
            serde_json::to_value(&joint_public.nodes).unwrap()
        );
        assert!(
            public.truncated_symbols.is_empty(),
            "two file-line sites do not exceed the public cap"
        );
        assert_eq!(public.edges.len(), 2);
        assert!(!public.complete, "unproven evidence survives aggregation");
    }

    #[test]
    fn disjoint_projection_rejects_overlap_even_when_an_admitted_file_has_no_rows() {
        let empty_file = test_file("src/Empty.java");
        let projections = [
            projected_inventory([], HashSet::from_iter([empty_file.clone()]), &[]),
            projected_inventory([], HashSet::from_iter([empty_file]), &[]),
        ];
        let error = aggregate_disjoint_workspace_usage_projections(
            &projections,
            CANONICAL_GENERATION,
            &CancellationToken::default(),
        )
        .err()
        .expect("empty files still own caller admission");
        assert!(
            error
                .to_string()
                .contains("overlapping admitted caller files")
        );
        assert!(
            complete_disjoint_projection(&[])
                .admitted_callers()
                .is_empty()
        );
    }

    #[test]
    fn disjoint_projection_keeps_incomplete_evidence_and_generation_authority() {
        let mut projection =
            projected_inventory([], HashSet::from_iter([test_file("src/Empty.java")]), &[]);
        projection.forward_completeness = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::ReferenceEnumerationIncomplete],
        };
        projection.kind_projection_complete = false;
        let projections = [projection];
        match aggregate_disjoint_workspace_usage_projections(
            &projections,
            CANONICAL_GENERATION,
            &CancellationToken::default(),
        )
        .unwrap()
        {
            SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(merged) => {
                assert_eq!(
                    merged.forward_completeness,
                    projections[0].forward_completeness
                );
                assert!(!merged.kind_projection_complete);
                assert_eq!(merged.admitted_callers(), projections[0].admitted_callers());
            }
            _ => panic!("partial input cannot certify absence"),
        }
        assert!(matches!(
            aggregate_disjoint_workspace_usage_projections(
                &projections,
                CANONICAL_GENERATION + 1,
                &CancellationToken::default()
            )
            .unwrap(),
            SelectedWorkspaceUsageGraphProjectionOutcome::Stale
        ));
        let mut projection = projections.into_iter().next().unwrap();
        projection.forward_completeness = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::Cancelled],
        };
        assert!(matches!(
            aggregate_disjoint_workspace_usage_projections(
                &[projection],
                CANONICAL_GENERATION,
                &CancellationToken::default()
            )
            .unwrap(),
            SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled
        ));
    }

    #[test]
    fn disjoint_projection_preserves_independent_completion_dimensions() {
        for reason in [
            EdgeIncompleteReason::ReferenceEnumerationIncomplete,
            EdgeIncompleteReason::ForwardResolutionIncomplete,
            EdgeIncompleteReason::ForwardAdmissionIncomplete,
            EdgeIncompleteReason::ForwardMetadataIncomplete,
        ] {
            let mut projection =
                projected_inventory([], HashSet::from_iter([test_file("src/Empty.java")]), &[]);
            projection.forward_completeness = EdgeCompleteness::Incomplete {
                reasons: vec![reason],
            };
            let projections = [projection];
            match aggregate_disjoint_workspace_usage_projections(
                &projections,
                CANONICAL_GENERATION,
                &CancellationToken::default(),
            )
            .unwrap()
            {
                SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(merged) => {
                    assert_eq!(
                        merged.forward_completeness,
                        projections[0].forward_completeness
                    );
                    assert!(merged.kind_projection_complete);
                }
                _ => panic!("exact kinds cannot erase incomplete forward semantics"),
            }
        }

        let mut projection =
            projected_inventory([], HashSet::from_iter([test_file("src/Empty.java")]), &[]);
        projection.kind_projection_complete = false;
        match aggregate_disjoint_workspace_usage_projections(
            &[projection],
            CANONICAL_GENERATION,
            &CancellationToken::default(),
        )
        .unwrap()
        {
            SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(merged) => {
                assert_eq!(merged.forward_completeness, EdgeCompleteness::Complete);
                assert!(!merged.kind_projection_complete);
            }
            _ => panic!("complete forward enumeration cannot erase inexact kinds"),
        }
    }

    #[test]
    fn disjoint_projection_cancellation_discards_all_staging_and_preserves_inputs() {
        let caller = test_unit(
            &test_file("src/Caller.java"),
            CodeUnitType::Function,
            "Caller.run",
        );
        let target = test_unit(
            &test_file("dep/Target.java"),
            CodeUnitType::Function,
            "Target.run",
        );
        let projections = [remapping_projection(
            &caller,
            &target,
            UsageReferenceKind::Call,
        )];
        let original_edges = projections[0].edges.clone();
        let mut late_cancelled = false;
        let mut finished = false;
        for checks in 1..=128 {
            match aggregate_disjoint_workspace_usage_projections(
                &projections,
                CANONICAL_GENERATION,
                &CancellationToken::cancel_after_checks_for_test(checks),
            )
            .unwrap()
            {
                SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled => {
                    late_cancelled |= checks > 25
                }
                SelectedWorkspaceUsageGraphProjectionOutcome::Complete(projection) => {
                    assert_eq!(projection.edges, original_edges);
                    finished = true;
                    break;
                }
                _ => panic!("complete stable fixture cannot be stale or partial"),
            }
        }
        assert!(late_cancelled && finished);
        assert_eq!(projections[0].edges, original_edges);
        assert_eq!(
            complete_disjoint_projection(&projections).edges,
            original_edges
        );
    }

    #[test]
    #[should_panic(
        expected = "canonical graph rows must belong to explicitly admitted caller files"
    )]
    fn canonical_projection_rejects_rows_outside_explicit_empty_admission() {
        let file = test_file("src/Caller.java");
        let caller = test_unit(&file, CodeUnitType::Function, "Caller.run");
        let target = test_unit(
            &test_file("dep/Target.java"),
            CodeUnitType::Function,
            "Target.run",
        );
        let row = canonical_row(
            &file,
            test_range(100, 101, 7),
            &caller,
            &target,
            Some(ReferenceKind::MethodCall),
            UsageProof::Proven,
        );
        projected_inventory([caller, target], HashSet::default(), &[row]);
    }

    #[test]
    fn projection_node_remapping_retains_distinct_mounted_targets_and_dependency_nodes() {
        let first = test_unit(
            &test_file("src/First.java"),
            CodeUnitType::Function,
            "First.run",
        );
        let second = test_unit(
            &test_file("src/Second.java"),
            CodeUnitType::Function,
            "Second.run",
        );
        let target_a = test_unit(
            &test_file("dep-a/Target.java"),
            CodeUnitType::Function,
            "Target.run",
        );
        let target_b = test_unit(
            &test_file("dep-b/Target.java"),
            CodeUnitType::Function,
            "Target.run",
        );
        assert_eq!(target_a.fq_name(), target_b.fq_name());
        assert_ne!(target_a.declaration_id(), target_b.declaration_id());
        let mut initial = canonical_catalog([(first.clone(), Vec::new())])
            .catalog
            .nodes;
        initial[0].truncated_inbound = Some(MAX_CALLSITES + 1);
        initial[0].unproven_inbound = 3;
        let projections = [
            remapping_projection(&first, &target_a, UsageReferenceKind::Call),
            remapping_projection(&second, &target_b, UsageReferenceKind::Type),
        ];
        let mapping = ready_node_remapping(&initial, &projections);
        assert_eq!(mapping.generation, CANONICAL_GENERATION);
        assert_eq!(mapping.declarations.len(), 4);
        assert!(std::ptr::eq(mapping.initial_nodes, initial.as_slice()));
        let initial_index = mapping.initial_node_indices[0];
        assert_eq!(mapping.declarations[initial_index].primary, &first);
        assert_eq!(initial[0].primary_range, None);
        assert_eq!(
            mapping.initial_nodes[0].truncated_inbound,
            Some(MAX_CALLSITES + 1)
        );
        assert_eq!(mapping.initial_nodes[0].unproven_inbound, 3);
        assert_eq!(
            mapping.declarations[initial_index].primary_range,
            Some(test_range(0, 80, 1))
        );
        for (index, (caller, target)) in [(&first, &target_a), (&second, &target_b)]
            .into_iter()
            .enumerate()
        {
            let remapped = &mapping.projections[index];
            assert!(std::ptr::eq(remapped.projection, &projections[index]));
            let edges = remapped.edges().collect::<Vec<_>>();
            assert_eq!(edges.len(), 1);
            assert_eq!(
                mapping.declarations[edges[0].from].key.id,
                caller.declaration_id()
            );
            assert_eq!(
                mapping.declarations[edges[0].to].key.id,
                target.declaration_id()
            );
            assert_eq!(edges[0].counts, projections[index].edges[0].counts);
            assert_eq!(edges[0].sites, &[(caller.source().clone(), 7)]);
            assert!(std::ptr::eq(
                edges[0].sites,
                projections[index].edges[0].sites.as_slice()
            ));
        }
    }

    #[test]
    fn projection_node_remapping_keeps_overlapping_counts_and_evidence_separate() {
        let caller = test_unit(
            &test_file("src/Caller.java"),
            CodeUnitType::Function,
            "Caller.run",
        );
        let target = test_unit(
            &test_file("dep/Target.java"),
            CodeUnitType::Function,
            "Target.run",
        );
        let mut projections = [
            remapping_projection(&caller, &target, UsageReferenceKind::Call),
            remapping_projection(&caller, &target, UsageReferenceKind::Type),
        ];
        let first_target = projections[0].edges[0].to;
        projections[0].nodes[first_target].truncated_inbound = Some(MAX_CALLSITES + 1);
        projections[0].nodes[first_target].unproven_inbound = 2;
        projections[0].forward_completeness = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::ReferenceEnumerationIncomplete],
        };
        let second_target = projections[1].edges[0].to;
        projections[1].nodes[second_target].unproven_inbound = 3;
        projections[1].kind_projection_complete = false;
        projections[1].reference_count = 17;
        let mapping = ready_node_remapping(&[], &projections);
        assert_eq!(mapping.declarations.len(), 2);
        assert_eq!(mapping.projections.len(), 2);
        let first_edge = mapping.projections[0].edges().next().unwrap();
        let second_edge = mapping.projections[1].edges().next().unwrap();
        assert_eq!(
            (first_edge.from, first_edge.to),
            (second_edge.from, second_edge.to)
        );
        assert_eq!(first_edge.sites, second_edge.sites);
        assert_eq!(
            first_edge.counts,
            UsageReferenceCounts {
                calls: 1,
                ..Default::default()
            }
        );
        assert_eq!(
            second_edge.counts,
            UsageReferenceCounts {
                types: 1,
                ..Default::default()
            }
        );
        for (index, remapped) in mapping.projections.iter().enumerate() {
            let original = &projections[index];
            assert!(std::ptr::eq(remapped.projection, original));
            assert_eq!(
                remapped.projection.forward_completeness,
                original.forward_completeness
            );
            assert_eq!(
                remapped.projection.kind_projection_complete,
                original.kind_projection_complete
            );
            assert_eq!(
                remapped.projection.reference_count,
                original.reference_count
            );
            assert_eq!(remapped.projection.projected_edge_count, 9);
            assert_eq!(remapped.projection.batch_count, 3);
            assert_eq!(
                remapped.projection.root_binding_metrics,
                original.root_binding_metrics
            );
            for (local, node) in original.nodes.iter().enumerate() {
                assert_eq!(
                    mapping.declarations[remapped.node_indices[local]].key.id,
                    node.key.id
                );
            }
        }
        assert_eq!(
            mapping.projections[0].projection.nodes[first_target].truncated_inbound,
            Some(MAX_CALLSITES + 1)
        );
        assert_eq!(
            mapping.projections[0].projection.nodes[first_target].unproven_inbound,
            2
        );
        assert_eq!(
            mapping.projections[1].projection.nodes[second_target].truncated_inbound,
            None
        );
        assert_eq!(
            mapping.projections[1].projection.nodes[second_target].unproven_inbound,
            3
        );
    }

    #[test]
    fn projection_node_remapping_numbering_is_independent_of_contribution_order() {
        let first = test_unit(
            &test_file("src/First.java"),
            CodeUnitType::Function,
            "First.run",
        );
        let second = test_unit(
            &test_file("src/Second.java"),
            CodeUnitType::Function,
            "Second.run",
        );
        let target = test_unit(
            &test_file("dep/Target.java"),
            CodeUnitType::Function,
            "Target.run",
        );
        let mut projections = [
            remapping_projection(&first, &target, UsageReferenceKind::Call),
            remapping_projection(&second, &target, UsageReferenceKind::Type),
        ];
        let signature = |projections: &[SelectedWorkspaceUsageGraphProjection]| {
            let mapping = ready_node_remapping(&[], projections);
            let ids = mapping
                .declarations
                .iter()
                .map(|node| node.key.id.clone())
                .collect::<Vec<_>>();
            let mut edges = mapping
                .projections
                .iter()
                .flat_map(|projection| {
                    projection
                        .edges()
                        .map(|edge| (edge.from, edge.to, edge.counts.calls, edge.counts.types))
                })
                .collect::<Vec<_>>();
            edges.sort_unstable();
            (ids, edges)
        };
        let forward = signature(&projections);
        projections.reverse();
        assert_eq!(signature(&projections), forward);
        assert_eq!(forward.0.len(), 3);
    }

    #[test]
    fn disjoint_projection_dependency_ranges_are_independent_of_contribution_order() {
        let first = test_unit(
            &test_file("src/First.java"),
            CodeUnitType::Function,
            "First.run",
        );
        let second = test_unit(
            &test_file("src/Second.java"),
            CodeUnitType::Function,
            "Second.run",
        );
        let target = test_unit(
            &test_file("dep/Target.java"),
            CodeUnitType::Function,
            "Target.run",
        );
        let mut projections = [
            remapping_projection(&first, &target, UsageReferenceKind::Call),
            remapping_projection(&second, &target, UsageReferenceKind::Type),
        ];
        let target_index = projections[1].edges[0].to;
        projections[1].nodes[target_index].primary_range = Some(test_range(0, 100, 2));
        let forward = complete_disjoint_projection(&projections);
        projections.reverse();
        let reverse = complete_disjoint_projection(&projections);
        for (left, right) in forward.nodes.iter().zip(&reverse.nodes) {
            assert_eq!(left.key, right.key);
            assert_eq!(left.primary_range, right.primary_range);
            assert_eq!(left.declaration_files, right.declaration_files);
            assert_eq!(left.declaration_ids, right.declaration_ids);
        }
        assert_eq!(forward.edges, reverse.edges);
    }

    #[test]
    fn mixed_graph_merge_keeps_exact_endpoints_and_initial_inbound_evidence() {
        let caller = test_unit(
            &test_file("src/Caller.java"),
            CodeUnitType::Function,
            "Caller.run",
        );
        let target = test_unit(
            &test_file("dep/Target.java"),
            CodeUnitType::Function,
            "Target.run",
        );
        let other_target = test_unit(
            &test_file("other/Target.java"),
            CodeUnitType::Function,
            "Target.run",
        );
        let mut initial = canonical_catalog([
            (caller.clone(), Vec::new()),
            (other_target.clone(), Vec::new()),
        ])
        .catalog
        .nodes;
        let other_index = initial
            .iter()
            .position(|node| node.key.id == other_target.declaration_id())
            .unwrap();
        initial[other_index].unproven_inbound = 3;
        initial[other_index].truncated_inbound = Some(MAX_CALLSITES + 1);
        let projection = remapping_projection(&caller, &target, UsageReferenceKind::Call);
        let graph = WorkspaceUsageGraph {
            nodes: initial,
            edges: Vec::new(),
            resolved_ecosystems: Vec::new(),
        };
        let WorkspaceUsageGraphBuildOutcome::Complete(merged) =
            merge_workspace_usage_graph_projections(
                graph,
                &[projection],
                CANONICAL_GENERATION,
                &CancellationToken::default(),
            )
        else {
            panic!("same-generation mixed graph must merge");
        };
        assert_eq!(merged.nodes.len(), 3);
        assert_eq!(merged.edges.len(), 1);
        assert_eq!(
            merged.nodes[merged.edges[0].from].key.id,
            caller.declaration_id()
        );
        assert_eq!(
            merged.nodes[merged.edges[0].to].key.id,
            target.declaration_id()
        );
        let retained = &merged.nodes[node_index(&merged, &other_target)];
        assert_eq!(retained.unproven_inbound, 3);
        assert_eq!(retained.truncated_inbound, Some(MAX_CALLSITES + 1));
    }

    #[test]
    fn projection_node_remapping_checks_empty_and_contributed_generations() {
        let cancellation = CancellationToken::default();
        assert!(matches!(
            remap_workspace_usage_projection_nodes(&[], CANONICAL_GENERATION, &[], CANONICAL_GENERATION + 1, &cancellation),
            CanonicalWorkspaceUsageNodeRemappingOutcome::Stale { expected, actual }
                if expected == CANONICAL_GENERATION + 1 && actual == CANONICAL_GENERATION
        ));
        let empty = ready_node_remapping(&[], &[]);
        assert_eq!(empty.generation, CANONICAL_GENERATION);
        assert!(empty.declarations.is_empty());
        assert!(empty.initial_node_indices.is_empty());
        assert!(empty.projections.is_empty());
        let caller = test_unit(
            &test_file("src/Caller.java"),
            CodeUnitType::Function,
            "Caller.run",
        );
        let target = test_unit(
            &test_file("dep/Target.java"),
            CodeUnitType::Function,
            "Target.run",
        );
        let mut projection = remapping_projection(&caller, &target, UsageReferenceKind::Call);
        projection.generation += 1;
        assert!(matches!(
            remap_workspace_usage_projection_nodes(&[], CANONICAL_GENERATION, &[projection], CANONICAL_GENERATION, &cancellation),
            CanonicalWorkspaceUsageNodeRemappingOutcome::Stale { expected, actual }
                if expected == CANONICAL_GENERATION && actual == CANONICAL_GENERATION + 1
        ));
    }

    #[test]
    fn projection_node_remapping_cancellation_never_publishes_partial_indices() {
        let caller = test_unit(
            &test_file("src/Caller.java"),
            CodeUnitType::Function,
            "Caller.run",
        );
        let target = test_unit(
            &test_file("dep/Target.java"),
            CodeUnitType::Function,
            "Target.run",
        );
        let projections = [remapping_projection(
            &caller,
            &target,
            UsageReferenceKind::Call,
        )];
        let initial = projections[0].nodes.as_slice();
        let original_edges = projections[0].edges.clone();
        let mut cancelled_during_staging = false;
        let mut exhausted = false;
        for checks in 1..=64 {
            match remap_workspace_usage_projection_nodes(
                initial,
                CANONICAL_GENERATION,
                &projections,
                CANONICAL_GENERATION,
                &CancellationToken::cancel_after_checks_for_test(checks),
            ) {
                CanonicalWorkspaceUsageNodeRemappingOutcome::Cancelled => {
                    cancelled_during_staging |= checks > 10;
                }
                CanonicalWorkspaceUsageNodeRemappingOutcome::Ready(mapping) => {
                    assert_eq!(mapping.initial_node_indices.len(), initial.len());
                    assert_eq!(mapping.projections[0].node_indices.len(), initial.len());
                    exhausted = true;
                    break;
                }
                CanonicalWorkspaceUsageNodeRemappingOutcome::Stale { .. } => {
                    panic!("generation did not change")
                }
            }
        }
        assert!(cancelled_during_staging && exhausted);
        assert_eq!(projections[0].edges, original_edges);
        assert_eq!(
            ready_node_remapping(initial, &projections)
                .declarations
                .len(),
            2
        );
    }

    #[test]
    #[should_panic(expected = "one DeclarationId must retain compatible graph identity metadata")]
    fn projection_node_remapping_rejects_conflicting_identity_metadata() {
        let caller = test_unit(
            &test_file("src/Caller.java"),
            CodeUnitType::Function,
            "Caller.run",
        );
        let target = test_unit(
            &test_file("dep/Target.java"),
            CodeUnitType::Function,
            "Target.run",
        );
        let initial = canonical_catalog([(caller.clone(), Vec::new())])
            .catalog
            .nodes;
        let mut projection = remapping_projection(&caller, &target, UsageReferenceKind::Call);
        let caller_node = projection.edges[0].from;
        projection.nodes[caller_node].key.ecosystem = UsageEcosystem::Rust;
        ready_node_remapping(&initial, &[projection]);
    }

    #[test]
    fn canonical_accumulator_accepts_a_valid_empty_batch_stream() {
        let mut accumulator = CanonicalWorkspaceUsageGraphAccumulator::new(
            canonical_catalog(std::iter::empty::<(CodeUnit, Vec<Range>)>()),
            BTreeSet::from([UsageEcosystem::Jvm]),
            HashSet::default(),
        );
        let cancellation = CancellationToken::default();
        assert!(accumulator.stage_rows(&[], &cancellation));
        assert!(accumulator.stage_rows(&[], &cancellation));

        let graph = complete_canonical_graph(accumulator.finish(
            CANONICAL_GENERATION,
            &EdgeCompleteness::Complete,
            &cancellation,
        ));
        assert!(graph.nodes.is_empty());
        assert!(graph.edges.is_empty());
    }

    #[test]
    fn canonical_accumulator_cancellation_discards_a_staged_prefix() {
        let caller_file = test_file("src/Caller.java");
        let target_file = test_file("src/Target.java");
        let caller = test_unit(&caller_file, CodeUnitType::Function, "Caller.run");
        let target = test_unit(&target_file, CodeUnitType::Function, "Target.run");
        let mut accumulator = CanonicalWorkspaceUsageGraphAccumulator::new(
            canonical_catalog([
                (caller.clone(), vec![test_range(0, 80, 1)]),
                (target.clone(), vec![test_range(0, 80, 1)]),
            ]),
            BTreeSet::from([UsageEcosystem::Jvm]),
            HashSet::from_iter([caller_file.clone()]),
        );
        let row = canonical_row(
            &caller_file,
            test_range(100, 106, 7),
            &caller,
            &target,
            Some(ReferenceKind::MethodCall),
            UsageProof::Proven,
        );
        let cancellation = CancellationToken::default();
        assert!(accumulator.stage_rows(&[row], &cancellation));
        cancellation.cancel();

        assert!(matches!(
            accumulator.finish(
                CANONICAL_GENERATION,
                &EdgeCompleteness::Complete,
                &cancellation,
            ),
            CanonicalWorkspaceUsageGraphBuildOutcome::Cancelled
        ));
    }

    #[test]
    fn canonical_accumulator_is_batch_permutation_invariant() {
        let first_file = test_file("src/First.java");
        let second_file = test_file("src/Second.java");
        let target_file = test_file("src/Target.java");
        let first = test_unit(&first_file, CodeUnitType::Function, "First.run");
        let second = test_unit(&second_file, CodeUnitType::Function, "Second.run");
        let target = test_unit(&target_file, CodeUnitType::Function, "Target.run");
        let make_catalog = || {
            canonical_catalog([
                (first.clone(), vec![test_range(0, 80, 1)]),
                (second.clone(), vec![test_range(0, 80, 1)]),
                (target.clone(), vec![test_range(0, 80, 1)]),
            ])
        };
        let first_batch = [
            canonical_row(
                &first_file,
                test_range(100, 106, 7),
                &first,
                &target,
                Some(ReferenceKind::MethodCall),
                UsageProof::Proven,
            ),
            canonical_row(
                &second_file,
                test_range(140, 146, 9),
                &second,
                &target,
                Some(ReferenceKind::MethodCall),
                UsageProof::Unproven,
            ),
        ];
        let second_batch = [canonical_row(
            &first_file,
            test_range(110, 116, 7),
            &first,
            &target,
            Some(ReferenceKind::TypeReference),
            UsageProof::Proven,
        )];
        let selected = BTreeSet::from([UsageEcosystem::Jvm]);
        let cancellation = CancellationToken::default();
        let admitted = HashSet::from_iter([first_file.clone(), second_file.clone()]);
        let mut forward = CanonicalWorkspaceUsageGraphAccumulator::new(
            make_catalog(),
            selected.clone(),
            admitted.clone(),
        );
        assert!(forward.stage_rows(&first_batch, &cancellation));
        assert!(forward.stage_rows(&second_batch, &cancellation));
        let forward = complete_canonical_graph(forward.finish(
            CANONICAL_GENERATION,
            &EdgeCompleteness::Complete,
            &cancellation,
        ));

        let mut reverse =
            CanonicalWorkspaceUsageGraphAccumulator::new(make_catalog(), selected, admitted);
        assert!(reverse.stage_rows(&second_batch, &cancellation));
        assert!(reverse.stage_rows(&first_batch, &cancellation));
        let reverse = complete_canonical_graph(reverse.finish(
            CANONICAL_GENERATION,
            &EdgeCompleteness::Complete,
            &cancellation,
        ));

        assert_eq!(
            canonical_graph_signature(&forward),
            canonical_graph_signature(&reverse)
        );
    }

    #[test]
    fn canonical_projection_preserves_sorted_sites_and_proof_only_topology() {
        let caller_file = test_file("src/Caller.java");
        let other_file = test_file("src/Other.java");
        let target_file = test_file("src/Target.java");
        let caller = test_unit(&caller_file, CodeUnitType::Function, "Caller.run");
        let other = test_unit(&other_file, CodeUnitType::Function, "Other.run");
        let target = test_unit(&target_file, CodeUnitType::Function, "Target.run");
        let make_catalog = || {
            canonical_catalog([
                (caller.clone(), vec![test_range(0, 80, 1)]),
                (other.clone(), vec![test_range(0, 80, 1)]),
                (target.clone(), vec![test_range(0, 80, 1)]),
            ])
        };
        let first_batch = [
            canonical_row(
                &caller_file,
                test_range(120, 126, 8),
                &caller,
                &target,
                Some(ReferenceKind::TypeReference),
                UsageProof::Proven,
            ),
            canonical_row(
                &other_file,
                test_range(140, 146, 9),
                &other,
                &target,
                Some(ReferenceKind::MethodCall),
                UsageProof::Unproven,
            ),
        ];
        let second_batch = [
            canonical_row(
                &caller_file,
                test_range(110, 116, 7),
                &caller,
                &target,
                Some(ReferenceKind::TypeReference),
                UsageProof::Proven,
            ),
            canonical_row(
                &caller_file,
                test_range(100, 106, 7),
                &caller,
                &target,
                Some(ReferenceKind::MethodCall),
                UsageProof::Proven,
            ),
        ];
        let selected = BTreeSet::from([UsageEcosystem::Jvm]);
        let cancellation = CancellationToken::default();

        let admitted = HashSet::from_iter([caller_file.clone(), other_file.clone()]);
        let mut forward = CanonicalWorkspaceUsageGraphAccumulator::new(
            make_catalog(),
            selected.clone(),
            admitted.clone(),
        );
        assert!(forward.stage_rows(&first_batch, &cancellation));
        assert!(forward.stage_rows(&second_batch, &cancellation));
        let forward = complete_canonical_projection(forward.finish_projection(
            CANONICAL_GENERATION,
            &EdgeCompleteness::Complete,
            &cancellation,
        ));

        let mut reverse =
            CanonicalWorkspaceUsageGraphAccumulator::new(make_catalog(), selected, admitted);
        assert!(reverse.stage_rows(&second_batch, &cancellation));
        assert!(reverse.stage_rows(&first_batch, &cancellation));
        let reverse = complete_canonical_projection(reverse.finish_projection(
            CANONICAL_GENERATION,
            &EdgeCompleteness::Complete,
            &cancellation,
        ));

        assert_eq!(forward.edges, reverse.edges);
        assert_eq!(1, forward.edges.len());
        let edge = &forward.edges[0];
        assert!(
            forward.nodes[edge.from]
                .declaration_ids
                .contains(&caller.declaration_id())
        );
        assert!(
            forward.nodes[edge.to]
                .declaration_ids
                .contains(&target.declaration_id())
        );
        assert_eq!(1, edge.counts.calls);
        assert_eq!(1, edge.counts.types);
        assert_eq!(vec![(caller_file.clone(), 7), (caller_file, 8)], edge.sites);
        assert_eq!(1, forward.nodes[edge.to].unproven_inbound);
        assert!(forward.edges.iter().all(|edge| {
            !forward.nodes[edge.from]
                .declaration_ids
                .contains(&other.declaration_id())
        }));
    }

    #[test]
    fn canonical_projection_retains_one_public_line_past_the_raw_ranking_cap() {
        let caller_file = test_file("src/Caller.java");
        let target_file = test_file("src/Target.java");
        let caller = test_unit(&caller_file, CodeUnitType::Function, "Caller.run");
        let target = test_unit(&target_file, CodeUnitType::Function, "Target.run");
        let mut accumulator = CanonicalWorkspaceUsageGraphAccumulator::new(
            canonical_catalog([
                (caller.clone(), vec![test_range(0, 80, 1)]),
                (target.clone(), vec![test_range(0, 80, 1)]),
            ]),
            BTreeSet::from([UsageEcosystem::Jvm]),
            HashSet::from_iter([caller_file.clone()]),
        );
        let rows = (0..=MAX_CALLSITES)
            .map(|index| {
                let start = 100 + index * 2;
                canonical_row(
                    &caller_file,
                    test_range(start, start + 1, 7),
                    &caller,
                    &target,
                    Some(ReferenceKind::MethodCall),
                    UsageProof::Proven,
                )
            })
            .collect::<Vec<_>>();
        let cancellation = CancellationToken::default();
        assert!(accumulator.stage_rows(&rows, &cancellation));
        let projection = complete_canonical_projection(accumulator.finish_projection(
            CANONICAL_GENERATION,
            &EdgeCompleteness::Complete,
            &cancellation,
        ));
        let target_index = projection
            .nodes
            .iter()
            .position(|node| node.declaration_ids.contains(&target.declaration_id()))
            .expect("the target must be cataloged");
        assert_eq!(
            Some(MAX_CALLSITES + 1),
            projection.nodes[target_index].truncated_inbound
        );
        assert_eq!(1, projection.edges.len());
        assert_eq!(vec![(caller_file, 7)], projection.edges[0].sites);

        let ranking = projection
            .into_workspace_graph(&cancellation)
            .expect("the uncancelled ranking conversion must finish");
        assert!(
            ranking.edges.is_empty(),
            "the established byte-site ranking cap remains unchanged"
        );
    }

    #[test]
    fn selected_java_coverage_rejects_catalog_and_snapshot_subsets() {
        const FIRST_SOURCE: &str = "package fixture;\nclass First { void run() {} }\n";
        const SECOND_SOURCE: &str = "package fixture;\nclass Second { void run() {} }\n";
        let project = InlineTestProject::with_language(Language::Java)
            .file("src/First.java", FIRST_SOURCE)
            .file("src/Second.java", SECOND_SOURCE)
            .build();
        let first_file = project.file("src/First.java");
        let analyzer = JavaAnalyzer::new(project.project_dyn());
        let facts = crate::native_resolution_test_support::parse_java_resolution_facts(
            &first_file,
            FIRST_SOURCE,
        );
        let fragment = BindingFragmentId::for_test(b"workspace-coverage-first");
        let lexical = crate::analyzer::resolution::lower_for_test(fragment, Language::Java, &facts)
            .lexical()
            .clone();
        let typed = crate::analyzer::resolution::lower_for_test(fragment, Language::Java, &facts)
            .typed()
            .clone();
        let service = PreloadedFactResolutionService::from_lowered_fragments(
            [lexical.clone()],
            [typed.clone()],
        );
        let engine = SelectedFactResolutionEngine::new(&service);
        let selected = engine
            .snapshot(&CancellationToken::default())
            .expect("the selected Java coverage snapshot must build");
        let edge_catalog = FactReferenceEdgeCatalog::from_selected_fragments(
            &analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                first_file,
                FIRST_SOURCE,
                &facts,
                &lexical,
                &typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::default(),
        )
        .expect("the selected Java edge catalog must validate")
        .expect("uncancelled catalog construction must publish");
        let workspace_catalog = CanonicalWorkspaceUsageCatalog::build_with_cancellation(
            &analyzer,
            &CancellationToken::default(),
        )
        .expect("the stable workspace catalog must build");

        let error = validate_selected_workspace_coverage(
            &analyzer,
            &selected,
            &edge_catalog,
            &workspace_catalog,
            &CancellationToken::default(),
        )
        .expect_err("one selected file cannot certify a two-file Java workspace");
        assert!(
            error
                .to_string()
                .contains("does not cover the complete analyzed workspace"),
            "unexpected coverage error: {error}"
        );

        let other_fragment = BindingFragmentId::for_test(b"workspace-coverage-other");
        let other_lexical =
            crate::analyzer::resolution::lower_for_test(other_fragment, Language::Java, &facts)
                .lexical()
                .clone();
        let other_typed =
            crate::analyzer::resolution::lower_for_test(other_fragment, Language::Java, &facts)
                .typed()
                .clone();
        let other_service =
            PreloadedFactResolutionService::from_lowered_fragments([other_lexical], [other_typed]);
        let other_engine = SelectedFactResolutionEngine::new(&other_service);
        let other_selection = other_engine
            .snapshot(&CancellationToken::default())
            .expect("the alternate selected placement snapshot must build");
        let error = validate_selected_workspace_coverage(
            &analyzer,
            &other_selection,
            &edge_catalog,
            &workspace_catalog,
            &CancellationToken::default(),
        )
        .expect_err("a snapshot subset cannot borrow a larger edge catalog");
        assert!(
            error.to_string().contains("cover different fragments"),
            "unexpected snapshot coverage error: {error}"
        );
    }

    #[derive(Debug, PartialEq, Eq)]
    struct SelectedJavaBuildMetrics {
        complete: bool,
        generation: u64,
        reference_count: usize,
        projected_edge_count: usize,
        batch_count: usize,
        node_count: usize,
        edge_count: usize,
        incomplete_node_count: usize,
        retained_bytes: usize,
    }

    fn selected_java_build_metrics(
        outcome: SelectedWorkspaceUsageRankingBuildOutcome,
    ) -> SelectedJavaBuildMetrics {
        let (complete, graph) = match outcome {
            SelectedWorkspaceUsageRankingBuildOutcome::Complete(graph) => (true, graph),
            SelectedWorkspaceUsageRankingBuildOutcome::Incomplete(graph) => (false, graph),
            SelectedWorkspaceUsageRankingBuildOutcome::Cancelled => {
                panic!("an uncancelled selected Java build must publish a graph")
            }
            SelectedWorkspaceUsageRankingBuildOutcome::Stale => {
                panic!("a stable selected Java build must not be stale")
            }
            SelectedWorkspaceUsageRankingBuildOutcome::Unavailable(reason) => {
                panic!("selected Java graph inputs must be available: {reason}")
            }
        };
        SelectedJavaBuildMetrics {
            complete,
            generation: graph.generation(),
            reference_count: graph.reference_count(),
            projected_edge_count: graph.projected_edge_count(),
            batch_count: graph.batch_count(),
            node_count: graph.node_count(),
            edge_count: graph.edge_count(),
            incomplete_node_count: graph.incomplete_node_count(),
            retained_bytes: graph.retained_bytes(),
        }
    }

    fn selected_java_ranking_adapter_fixture() -> (
        BuiltInlineTestProject,
        SelectedWorkspaceUsageRankingGraph,
        ProjectFile,
        Vec<ProjectFile>,
    ) {
        let project = InlineTestProject::with_language(Language::Java)
            .file("src/Seed.java", "class Seed {}\n")
            .file("src/ZCallTarget.java", "class ZCallTarget {}\n")
            .file("src/AMemberTarget.java", "class AMemberTarget {}\n")
            .build();
        let seed = project.file("src/Seed.java");
        let call_target = project.file("src/ZCallTarget.java");
        let member_target = project.file("src/AMemberTarget.java");
        let mut node_indices_by_file = HashMap::default();
        node_indices_by_file.insert(seed.clone(), vec![0]);
        node_indices_by_file.insert(call_target.clone(), vec![1]);
        node_indices_by_file.insert(member_target.clone(), vec![2]);
        let graph = WorkspaceUsageRankingGraph {
            nodes: vec![
                WorkspaceUsageRankingNode {
                    primary_file: seed.clone(),
                    seed_files: vec![seed.clone()],
                    incomplete: false,
                    contains_tests: None,
                },
                WorkspaceUsageRankingNode {
                    primary_file: call_target.clone(),
                    seed_files: vec![call_target.clone()],
                    incomplete: false,
                    contains_tests: None,
                },
                WorkspaceUsageRankingNode {
                    primary_file: member_target.clone(),
                    seed_files: vec![member_target.clone()],
                    incomplete: false,
                    contains_tests: None,
                },
            ],
            edges: vec![
                WorkspaceUsageEdge {
                    from: 0,
                    to: 1,
                    counts: UsageReferenceCounts {
                        calls: 1,
                        ..UsageReferenceCounts::default()
                    },
                },
                WorkspaceUsageEdge {
                    from: 0,
                    to: 2,
                    counts: UsageReferenceCounts {
                        members: 1,
                        ..UsageReferenceCounts::default()
                    },
                },
            ],
            node_indices_by_file,
            resolved_ecosystems: vec![UsageEcosystem::Jvm],
        };
        let graph = SelectedWorkspaceUsageRankingGraph {
            graph,
            generation: CANONICAL_GENERATION,
            reference_count: 2,
            projected_edge_count: 2,
            batch_count: 1,
        };
        (project, graph, seed, vec![call_target, member_target])
    }

    #[test]
    fn selected_java_ranking_cancellation_publishes_no_prefix_and_retry_is_exact() {
        let (_project, graph, seed, expected_files) = selected_java_ranking_adapter_fixture();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        assert!(
            graph
                .rank_files_with_cancellation(&[(seed.clone(), 1.0)], 10, &cancellation)
                .is_none(),
            "a cancelled exact rank must publish no candidate prefix"
        );

        let retry = graph
            .rank_files_with_cancellation(&[(seed, 1.0)], 10, &CancellationToken::default())
            .expect("a fresh exact-ranking retry must finish");
        assert_eq!(
            retry.iter().map(|(file, _)| file).collect::<Vec<_>>(),
            expected_files.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn selected_java_ranking_pre_cancelled_fast_paths_never_publish_empty_success() {
        let (_project, mut graph, seed, _) = selected_java_ranking_adapter_fixture();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        assert!(
            graph
                .rank_files_with_cancellation(&[(seed.clone(), 1.0)], 0, &cancellation)
                .is_none(),
            "cancellation must outrank the incumbent zero-limit fast path"
        );

        graph.graph.edges.clear();
        assert!(
            graph
                .rank_files_with_cancellation(&[(seed, 1.0)], 10, &cancellation)
                .is_none(),
            "cancellation must outrank the incumbent edgeless-graph fast path"
        );
    }

    #[test]
    fn selected_java_ranking_reuses_one_graph_deterministically_without_mutation() {
        let (_project, graph, seed, expected_files) = selected_java_ranking_adapter_fixture();
        let before = (
            graph.generation(),
            graph.reference_count(),
            graph.projected_edge_count(),
            graph.batch_count(),
            graph.node_count(),
            graph.edge_count(),
            graph.incomplete_node_count(),
            graph.retained_bytes(),
        );
        let nodes = graph.graph.nodes.as_ptr();
        let edges = graph.graph.edges.as_ptr();

        let first = graph
            .rank_files_with_cancellation(&[(seed.clone(), 1.0)], 10, &CancellationToken::default())
            .expect("the first exact ranking must finish");
        let warm = graph
            .rank_files_with_cancellation(&[(seed, 1.0)], 10, &CancellationToken::default())
            .expect("the warm exact ranking must finish");

        assert_eq!(first, warm, "warm reranking must be deterministic");
        assert_eq!(
            first.iter().map(|(file, _)| file).collect::<Vec<_>>(),
            expected_files.iter().collect::<Vec<_>>()
        );
        assert_eq!(nodes, graph.graph.nodes.as_ptr());
        assert_eq!(edges, graph.graph.edges.as_ptr());
        assert_eq!(
            before,
            (
                graph.generation(),
                graph.reference_count(),
                graph.projected_edge_count(),
                graph.batch_count(),
                graph.node_count(),
                graph.edge_count(),
                graph.incomplete_node_count(),
                graph.retained_bytes(),
            ),
            "ranking must neither rebuild nor mutate the retained graph"
        );
    }

    #[test]
    fn selected_java_streamed_build_is_atomic_across_cancellation_and_retry() {
        // One selected top-level owner exercises the same nonconflicting Java
        // placement shape as the native edge projector's field-domain law.
        const SOURCE: &str =
            "package demo;\nclass Owner { int value; void write() { value = 1; } }\n";
        let project = InlineTestProject::with_language(Language::Java)
            .file("Owner.java", SOURCE)
            .build();
        let file = project.file("Owner.java");
        let overlay = Arc::new(OverlayProject::new(project.project_dyn()));
        let analyzer = JavaAnalyzer::new(overlay.clone());
        let facts =
            crate::native_resolution_test_support::parse_java_resolution_facts(&file, SOURCE);
        let fragment = BindingFragmentId::for_test(b"workspace-streamed-build");
        let lexical = crate::analyzer::resolution::lower_for_test(fragment, Language::Java, &facts)
            .lexical()
            .clone();
        let typed = crate::analyzer::resolution::lower_for_test(fragment, Language::Java, &facts)
            .typed()
            .clone();
        let service = PreloadedFactResolutionService::from_lowered_fragments(
            [lexical.clone()],
            [typed.clone()],
        );
        let snapshot = SelectedFactResolutionEngine::new(&service)
            .snapshot(&CancellationToken::default())
            .expect("the streamed selected Java snapshot must build");
        let edge_catalog = FactReferenceEdgeCatalog::from_selected_fragments(
            &analyzer,
            [FactReferenceEdgeSelectedFragment::new(
                file.clone(),
                SOURCE,
                &facts,
                &lexical,
                &typed,
                crate::analyzer::resolution::test_shared_names(),
            )],
            &CancellationToken::default(),
        )
        .expect("the streamed selected Java edge catalog must validate")
        .expect("uncancelled catalog construction must publish");

        let first = selected_java_build_metrics(
            build_selected_workspace_usage_ranking_graph(
                &analyzer,
                &snapshot,
                &edge_catalog,
                1,
                &CancellationToken::default(),
            )
            .expect("the streamed selected Java build must succeed"),
        );
        assert_eq!(first.generation, analyzer.project().analysis_generation());
        assert!(
            first.reference_count > 0,
            "the law fixture must enumerate references"
        );
        assert!(
            first.node_count > 0,
            "the law fixture must retain ranking nodes"
        );
        assert!(
            first.batch_count > 0,
            "a successful build must stage batches; complete={}",
            first.complete
        );
        assert!(
            first.edge_count <= first.projected_edge_count,
            "ranking edges are an aggregation of projected rows"
        );
        assert!(first.incomplete_node_count <= first.node_count);
        assert!(first.retained_bytes > 0);

        let mut public_telemetry =
            crate::native_resolution_test_support::SelectedUsageGraphTelemetry::default();
        let public = crate::native_resolution_test_support::build_selected_unscoped_usage_graph(
            &analyzer,
            &snapshot,
            &edge_catalog,
            1,
            &CancellationToken::default(),
            &mut public_telemetry,
        )
        .expect("the selected public graph facade must succeed");
        let (public_complete, public_result) = match public {
            crate::native_resolution_test_support::SelectedUsageGraphBuildOutcome::Complete(
                result,
            ) => (true, result),
            crate::native_resolution_test_support::SelectedUsageGraphBuildOutcome::Incomplete(
                result,
            ) => (false, result),
            crate::native_resolution_test_support::SelectedUsageGraphBuildOutcome::Cancelled => {
                panic!("an uncancelled selected public graph must not cancel")
            }
            crate::native_resolution_test_support::SelectedUsageGraphBuildOutcome::Stale => {
                panic!("a stable selected public graph must not be stale")
            }
        };
        assert!(public_telemetry.published);
        assert_eq!(public_complete, public_telemetry.complete);
        assert_eq!(public_complete, public_result.complete);
        assert_eq!(first.generation, public_telemetry.generation);
        assert_eq!(first.reference_count, public_telemetry.reference_count);
        assert_eq!(
            first.projected_edge_count,
            public_telemetry.projected_edge_count
        );
        assert_eq!(first.batch_count, public_telemetry.batch_count);
        assert!(
            public_telemetry.root_binding_metrics.reference_seeds() > 0,
            "the selected facade must publish the staging pass's root-binding work"
        );
        assert!(public_telemetry.root_binding_metrics.batches() > 0);
        assert!(
            public_telemetry.root_binding_metrics.successful_stitches()
                <= public_telemetry.root_binding_metrics.composition_attempts()
        );
        assert_eq!(public_result.nodes.len(), public_telemetry.node_count);
        assert_eq!(public_result.edges.len(), public_telemetry.edge_count);
        assert_eq!(
            public_result
                .edges
                .iter()
                .map(|edge| edge.sites.len())
                .sum::<usize>(),
            public_telemetry.site_count
        );

        let cancellation = CancellationToken::default();
        cancellation.cancel();
        assert!(matches!(
            build_selected_workspace_usage_ranking_graph(
                &analyzer,
                &snapshot,
                &edge_catalog,
                1,
                &cancellation,
            )
            .expect("cancellation is an explicit build outcome"),
            SelectedWorkspaceUsageRankingBuildOutcome::Cancelled
        ));
        let mut cancelled_telemetry =
            crate::native_resolution_test_support::SelectedUsageGraphTelemetry::default();
        assert!(matches!(
            crate::native_resolution_test_support::build_selected_unscoped_usage_graph(
                &analyzer,
                &snapshot,
                &edge_catalog,
                1,
                &cancellation,
                &mut cancelled_telemetry,
            )
            .expect("selected public graph cancellation is an explicit outcome"),
            crate::native_resolution_test_support::SelectedUsageGraphBuildOutcome::Cancelled
        ));
        assert_eq!(
            crate::native_resolution_test_support::SelectedUsageGraphTelemetry::default(),
            cancelled_telemetry,
            "cancelled publication must leave the telemetry sink empty"
        );

        let retry = selected_java_build_metrics(
            build_selected_workspace_usage_ranking_graph(
                &analyzer,
                &snapshot,
                &edge_catalog,
                1,
                &CancellationToken::default(),
            )
            .expect("an atomic retry must succeed"),
        );
        assert_eq!(
            retry, first,
            "cancellation must publish and retain no prefix"
        );

        assert!(overlay.set(file.abs_path(), format!("{SOURCE}// generation drift\n"),));
        let mut stale_telemetry =
            crate::native_resolution_test_support::SelectedUsageGraphTelemetry::default();
        assert!(matches!(
            crate::native_resolution_test_support::build_selected_unscoped_usage_graph(
                &analyzer,
                &snapshot,
                &edge_catalog,
                1,
                &CancellationToken::default(),
                &mut stale_telemetry,
            )
            .expect("selected public graph staleness is an explicit outcome"),
            crate::native_resolution_test_support::SelectedUsageGraphBuildOutcome::Stale
        ));
        assert_eq!(
            crate::native_resolution_test_support::SelectedUsageGraphTelemetry::default(),
            stale_telemetry,
            "stale publication must leave the telemetry sink empty"
        );
    }

    #[test]
    fn canonical_production_catalog_binds_full_ranges_and_java_module_scope_to_generation() {
        let project = InlineTestProject::with_language(Language::Java)
            .file("module-info.java", "module fixture.module {}\n")
            .file(
                "src/Target.java",
                "package fixture; class Target { void first() {} void second() {} }\n",
            )
            .build();
        let module_file = project.file("module-info.java");
        let analyzer = JavaAnalyzer::new(project.project_dyn());
        let generation = analyzer.project().analysis_generation();
        let catalog = CanonicalWorkspaceUsageCatalog::build_with_cancellation(
            &analyzer,
            &CancellationToken::default(),
        )
        .expect("a stable real analyzer snapshot must build a canonical catalog");

        assert_eq!(catalog.generation, generation);
        assert!(
            catalog.declaration_spans_by_node.len() == catalog.nodes().len(),
            "every canonical node must carry a complete range inventory"
        );
        for file in analyzer.analyzed_files() {
            for declaration in analyzer
                .declarations(&file)
                .into_iter()
                .filter(is_graph_declaration)
            {
                let index = catalog
                    .index_for_id(&declaration.declaration_id())
                    .unwrap_or_else(|| {
                        panic!("missing real graph declaration {}", declaration.fq_name())
                    });
                let spans = catalog.declaration_spans(index);
                for range in analyzer.ranges(&declaration) {
                    assert!(
                        spans.contains(&(declaration.source().clone(), range)),
                        "missing real declaration range for {}: {range:?} in {spans:?}",
                        declaration.fq_name()
                    );
                }
            }
        }

        let module_scope = CodeUnit::file_scope(module_file);
        assert!(
            catalog
                .index_for_id(&module_scope.declaration_id())
                .is_some(),
            "an analyzed Java module descriptor needs its graph-only file scope"
        );

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            CanonicalWorkspaceUsageCatalog::build_with_cancellation(&analyzer, &cancelled)
                .is_none(),
            "cancellation must publish no partial canonical catalog"
        );
    }

    #[test]
    fn canonical_workspace_boundary_ignores_only_field_target_kind_uncertainty() {
        const SOURCE: &str = "package fixture;\nclass Target { int value; void run() {} }\nclass Caller { void call(Target target) { target.value = 1; target.run(); } }\n";
        let project = InlineTestProject::with_language(Language::Java)
            .file("src/Fixture.java", SOURCE)
            .build();
        let file = project.file("src/Fixture.java");
        let analyzer = JavaAnalyzer::new(project.project_dyn());
        let declarations = analyzer.declarations(&file);
        let caller = declarations
            .iter()
            .find(|unit| unit.is_callable() && unit.terminal_name() == "call")
            .expect("the real Java analyzer must retain Caller.call")
            .clone();
        let target = declarations
            .iter()
            .find(|unit| unit.is_callable() && unit.terminal_name() == "run")
            .expect("the real Java analyzer must retain Target.run")
            .clone();
        let field = declarations
            .iter()
            .find(|unit| unit.is_field() && unit.terminal_name() == "value")
            .expect("the real Java analyzer must retain Target.value")
            .clone();
        let catalog = CanonicalWorkspaceUsageCatalog::build_with_cancellation(
            &analyzer,
            &CancellationToken::default(),
        )
        .expect("the real stable analyzer snapshot must build a canonical catalog");
        let generation = catalog.generation;
        assert!(
            catalog.index_for_id(&field.declaration_id()).is_none(),
            "canonical fields stay outside the workspace ranking node domain"
        );

        let value_start = SOURCE
            .find("target.value")
            .expect("the fixture must contain its field use")
            + "target.".len();
        let mut field_row = canonical_row(
            &file,
            test_range(value_start, value_start + "value".len(), 3),
            &caller,
            &field,
            None,
            UsageProof::Proven,
        );
        field_row.generation = generation;
        let canonical_completeness = EdgeCompleteness::Incomplete {
            reasons: vec![EdgeIncompleteReason::AxisUnsupported(
                EdgeAxis::KindClassification,
            )],
        };
        assert!(
            !canonical_completeness.covers(EdgeAxis::KindClassification),
            "the broad canonical stream still reports its field-only kind gap"
        );
        let field_graph = complete_canonical_graph(
            reduce_canonical_reference_edge_rows_to_workspace_usage_graph(
                catalog,
                &[field_row],
                generation,
                &EdgeCompleteness::Complete,
                &BTreeSet::from([UsageEcosystem::Jvm]),
                &CancellationToken::default(),
            ),
        );
        assert!(
            field_graph.edges.is_empty(),
            "a field target contributes no ranking topology"
        );

        let catalog = CanonicalWorkspaceUsageCatalog::build_with_cancellation(
            &analyzer,
            &CancellationToken::default(),
        )
        .expect("the same stable snapshot must rebuild exactly");
        let call_start = SOURCE
            .find("target.run")
            .expect("the fixture must contain its callable use")
            + "target.".len();
        let mut callable_row = canonical_row(
            &file,
            test_range(call_start, call_start + "run".len(), 3),
            &caller,
            &target,
            None,
            UsageProof::Proven,
        );
        callable_row.generation = generation;
        assert!(
            matches!(
                reduce_canonical_reference_edge_rows_to_workspace_usage_graph(
                    catalog,
                    &[callable_row],
                    generation,
                    &EdgeCompleteness::Complete,
                    &BTreeSet::from([UsageEcosystem::Jvm]),
                    &CancellationToken::default(),
                ),
                CanonicalWorkspaceUsageGraphBuildOutcome::Incomplete(_)
            ),
            "missing kind evidence on a rankable target must remain visible even if an upstream status incorrectly claims the axis"
        );
    }

    #[test]
    fn canonical_rows_deduplicate_lines_and_keep_the_strongest_kind() {
        let caller_file = test_file("src/Caller.java");
        let target_file = test_file("src/Target.java");
        let other_file = test_file("src/Other.java");
        let caller = test_unit(&caller_file, CodeUnitType::Function, "Caller.run");
        let target = test_unit(&target_file, CodeUnitType::Class, "Target");
        let other = test_unit(&other_file, CodeUnitType::Class, "Other");
        let catalog = canonical_catalog([
            (caller.clone(), vec![test_range(0, 80, 1)]),
            (target.clone(), vec![test_range(0, 80, 1)]),
            (other.clone(), vec![test_range(0, 80, 1)]),
        ]);
        let rows = vec![
            canonical_row(
                &caller_file,
                test_range(120, 126, 7),
                &caller,
                &target,
                Some(ReferenceKind::TypeReference),
                UsageProof::Proven,
            ),
            canonical_row(
                &caller_file,
                test_range(130, 136, 7),
                &caller,
                &target,
                Some(ReferenceKind::MethodCall),
                UsageProof::Proven,
            ),
            canonical_row(
                &caller_file,
                test_range(140, 146, 8),
                &caller,
                &target,
                Some(ReferenceKind::FieldRead),
                UsageProof::Proven,
            ),
            canonical_row(
                &caller_file,
                test_range(150, 156, 9),
                &caller,
                &other,
                Some(ReferenceKind::FieldWrite),
                UsageProof::Proven,
            ),
        ];
        let selected = BTreeSet::from([UsageEcosystem::Jvm]);
        let graph =
            complete_canonical_graph(reduce_canonical_reference_edges_to_workspace_usage_graph(
                catalog,
                &rows,
                &EdgeCompleteness::Complete,
                &selected,
                &CancellationToken::default(),
            ));

        let caller = node_index(&graph, &caller);
        let target = node_index(&graph, &target);
        let edge = graph
            .edges
            .iter()
            .find(|edge| edge.from == caller && edge.to == target)
            .expect("the proven caller-to-target edge must be retained");
        assert_eq!(
            edge.counts,
            UsageReferenceCounts {
                calls: 1,
                members: 1,
                ..UsageReferenceCounts::default()
            },
            "one file line is one weight and its strongest category wins"
        );
        assert!(
            graph
                .edges
                .windows(2)
                .all(|edges| (edges[0].from, edges[0].to) < (edges[1].from, edges[1].to)),
            "canonical edges must be strictly sorted by exact node indices"
        );
    }

    #[test]
    fn canonical_callsite_cap_deduplicates_bytes_and_counts_definition_overlap() {
        let caller_file = test_file("src/Caller.java");
        let target_file = test_file("src/Target.java");
        let caller = test_unit(&caller_file, CodeUnitType::Function, "Caller.run");
        let target = test_unit(&target_file, CodeUnitType::Class, "Target");
        let target_member = test_unit(&target_file, CodeUnitType::Function, "Target.inside");
        let make_catalog = || {
            canonical_catalog([
                (caller.clone(), vec![test_range(0, 80, 1)]),
                (target.clone(), vec![test_range(0, 50, 1)]),
                (target_member.clone(), vec![test_range(10, 20, 2)]),
            ])
        };
        let mut rows = (0..MAX_CALLSITES)
            .map(|index| {
                canonical_row(
                    &caller_file,
                    test_range(100 + index, 101 + index, 8),
                    &caller,
                    &target,
                    Some(ReferenceKind::FieldRead),
                    UsageProof::Proven,
                )
            })
            .collect::<Vec<_>>();
        rows.push(rows[0].clone());
        let selected = BTreeSet::from([UsageEcosystem::Jvm]);

        let graph_at_cap =
            complete_canonical_graph(reduce_canonical_reference_edges_to_workspace_usage_graph(
                make_catalog(),
                &rows,
                &EdgeCompleteness::Complete,
                &selected,
                &CancellationToken::default(),
            ));
        let target_at_cap = node_index(&graph_at_cap, &target);
        assert_eq!(graph_at_cap.nodes[target_at_cap].truncated_inbound, None);
        assert!(
            graph_at_cap
                .edges
                .iter()
                .any(|edge| edge.to == target_at_cap),
            "an exact duplicate byte offset must not push a target over the cap"
        );

        rows.push(canonical_row(
            &target_file,
            test_range(12, 13, 2),
            &target_member,
            &target,
            Some(ReferenceKind::FieldRead),
            UsageProof::Proven,
        ));
        let truncated =
            complete_canonical_graph(reduce_canonical_reference_edges_to_workspace_usage_graph(
                make_catalog(),
                &rows,
                &EdgeCompleteness::Complete,
                &selected,
                &CancellationToken::default(),
            ));
        let truncated_target = node_index(&truncated, &target);
        assert_eq!(
            truncated.nodes[truncated_target].truncated_inbound,
            Some(MAX_CALLSITES + 1),
            "the legacy cap counts a proven target site before definition-overlap exclusion"
        );
        assert!(
            truncated
                .edges
                .iter()
                .all(|edge| edge.to != truncated_target),
            "every proven inbound edge to a truncated target must be removed"
        );
    }

    #[test]
    fn canonical_unproven_rows_are_target_local_and_never_add_topology_or_cap() {
        let caller_file = test_file("src/Caller.java");
        let target_file = test_file("src/Target.java");
        let python_caller_file = test_file("src/caller.py");
        let python_target_file = test_file("src/target.py");
        let caller = test_unit(&caller_file, CodeUnitType::Function, "Caller.run");
        let target = test_unit(&target_file, CodeUnitType::Class, "Target");
        let python_caller = test_unit(
            &python_caller_file,
            CodeUnitType::Function,
            "PythonCaller.run",
        );
        let python_target = test_unit(&python_target_file, CodeUnitType::Class, "PythonTarget");
        let make_catalog = || {
            canonical_catalog([
                (caller.clone(), vec![test_range(0, 80, 1)]),
                (target.clone(), vec![test_range(0, 80, 1)]),
                (python_caller.clone(), vec![test_range(0, 80, 1)]),
                (python_target.clone(), vec![test_range(0, 80, 1)]),
            ])
        };
        let first = canonical_row(
            &caller_file,
            test_range(100, 106, 7),
            &caller,
            &target,
            Some(ReferenceKind::MethodCall),
            UsageProof::Unproven,
        );
        let rows = vec![
            first.clone(),
            first,
            canonical_row(
                &caller_file,
                test_range(120, 126, 8),
                &caller,
                &target,
                Some(ReferenceKind::MethodCall),
                UsageProof::Unproven,
            ),
            canonical_row(
                &python_caller_file,
                test_range(100, 106, 7),
                &python_caller,
                &python_target,
                Some(ReferenceKind::MethodCall),
                UsageProof::Unproven,
            ),
        ];
        let selected = BTreeSet::from([UsageEcosystem::Jvm]);
        let outcome = reduce_canonical_reference_edges_to_workspace_usage_graph(
            make_catalog(),
            &rows,
            &EdgeCompleteness::Incomplete {
                reasons: vec![EdgeIncompleteReason::ForwardResolutionIncomplete],
            },
            &selected,
            &CancellationToken::default(),
        );
        let CanonicalWorkspaceUsageGraphBuildOutcome::Incomplete(graph) = outcome else {
            panic!("incomplete forward input must produce an incomplete graph");
        };
        let target = node_index(&graph, &target);
        let python_target = node_index(&graph, &python_target);
        assert_eq!(graph.nodes[target].unproven_inbound, 2);
        assert_eq!(graph.nodes[target].truncated_inbound, None);
        assert_eq!(graph.nodes[python_target].unproven_inbound, 0);
        assert!(graph.edges.iter().all(|edge| edge.to != target));
        assert_eq!(graph.resolved_ecosystems, vec![UsageEcosystem::Jvm]);

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            reduce_canonical_reference_edges_to_workspace_usage_graph(
                make_catalog(),
                &rows,
                &EdgeCompleteness::Complete,
                &selected,
                &cancellation,
            ),
            CanonicalWorkspaceUsageGraphBuildOutcome::Cancelled
        ));
        assert!(matches!(
            reduce_canonical_reference_edges_to_workspace_usage_graph(
                make_catalog(),
                &rows,
                &EdgeCompleteness::Incomplete {
                    reasons: vec![EdgeIncompleteReason::Cancelled],
                },
                &selected,
                &CancellationToken::default(),
            ),
            CanonicalWorkspaceUsageGraphBuildOutcome::Cancelled
        ));
    }

    #[test]
    fn canonical_static_and_missing_kinds_are_other_and_keep_the_graph_incomplete() {
        let caller_file = test_file("src/Caller.java");
        let target_file = test_file("src/Target.java");
        let caller = test_unit(&caller_file, CodeUnitType::Function, "Caller.run");
        let target = test_unit(&target_file, CodeUnitType::Function, "Target.run");
        let catalog = canonical_catalog([
            (caller.clone(), vec![test_range(0, 80, 1)]),
            (target.clone(), vec![test_range(0, 80, 1)]),
        ]);
        let rows = vec![
            canonical_row(
                &caller_file,
                test_range(100, 106, 7),
                &caller,
                &target,
                Some(ReferenceKind::StaticReference),
                UsageProof::Proven,
            ),
            canonical_row(
                &caller_file,
                test_range(120, 126, 8),
                &caller,
                &target,
                None,
                UsageProof::Proven,
            ),
        ];
        let selected = BTreeSet::from([UsageEcosystem::Jvm]);
        let outcome = reduce_canonical_reference_edges_to_workspace_usage_graph(
            catalog,
            &rows,
            &EdgeCompleteness::Complete,
            &selected,
            &CancellationToken::default(),
        );
        let CanonicalWorkspaceUsageGraphBuildOutcome::Incomplete(graph) = outcome else {
            panic!("coarse static/missing kinds must keep exact weighting incomplete");
        };
        let caller = node_index(&graph, &caller);
        let target = node_index(&graph, &target);
        let edge = graph
            .edges
            .iter()
            .find(|edge| edge.from == caller && edge.to == target)
            .expect("best-effort rows must remain useful positive evidence");
        assert_eq!(
            edge.counts,
            UsageReferenceCounts {
                other: 2,
                ..UsageReferenceCounts::default()
            }
        );
    }

    #[test]
    fn canonical_complete_outcome_requires_every_ranking_axis() {
        let caller_file = test_file("src/Caller.java");
        let target_file = test_file("src/Target.java");
        let caller = test_unit(&caller_file, CodeUnitType::Function, "Caller.run");
        let target = test_unit(&target_file, CodeUnitType::Function, "Target.run");
        let make_catalog = || {
            canonical_catalog([
                (caller.clone(), vec![test_range(0, 80, 1)]),
                (target.clone(), vec![test_range(0, 80, 1)]),
            ])
        };
        let rows = [canonical_row(
            &caller_file,
            test_range(100, 106, 7),
            &caller,
            &target,
            Some(ReferenceKind::MethodCall),
            UsageProof::Proven,
        )];
        let selected = BTreeSet::from([UsageEcosystem::Jvm]);

        for axis in [
            EdgeAxis::ForwardProjection,
            EdgeAxis::OwnerClassification,
            EdgeAxis::KindClassification,
        ] {
            assert!(matches!(
                reduce_canonical_reference_edges_to_workspace_usage_graph(
                    make_catalog(),
                    &rows,
                    &EdgeCompleteness::Incomplete {
                        reasons: vec![EdgeIncompleteReason::AxisUnsupported(axis)],
                    },
                    &selected,
                    &CancellationToken::default(),
                ),
                CanonicalWorkspaceUsageGraphBuildOutcome::Incomplete(_)
            ));
        }
    }

    #[test]
    #[should_panic(expected = "row generation must match its catalog generation")]
    fn canonical_mixed_generation_rows_fail_closed() {
        let caller_file = test_file("src/Caller.java");
        let target_file = test_file("src/Target.java");
        let caller = test_unit(&caller_file, CodeUnitType::Function, "Caller.run");
        let target = test_unit(&target_file, CodeUnitType::Function, "Target.run");
        let catalog = canonical_catalog([
            (caller.clone(), vec![test_range(0, 80, 1)]),
            (target.clone(), vec![test_range(0, 80, 1)]),
        ]);
        let current = canonical_row(
            &caller_file,
            test_range(100, 106, 7),
            &caller,
            &target,
            Some(ReferenceKind::MethodCall),
            UsageProof::Proven,
        );
        let mut stale = current.clone();
        stale.generation = CANONICAL_GENERATION + 1;

        let _ = reduce_canonical_reference_edges_to_workspace_usage_graph(
            catalog,
            &[current, stale],
            &EdgeCompleteness::Complete,
            &BTreeSet::from([UsageEcosystem::Jvm]),
            &CancellationToken::default(),
        );
    }

    #[test]
    #[should_panic(expected = "status generation must match its catalog generation")]
    fn canonical_status_generation_mismatch_fails_closed_without_rows() {
        let target_file = test_file("src/Target.java");
        let target = test_unit(&target_file, CodeUnitType::Class, "Target");
        let catalog = canonical_catalog([(target, vec![test_range(0, 80, 1)])]);

        let _ = reduce_canonical_reference_edge_rows_to_workspace_usage_graph(
            catalog,
            &[],
            CANONICAL_GENERATION + 1,
            &EdgeCompleteness::Complete,
            &BTreeSet::from([UsageEcosystem::Jvm]),
            &CancellationToken::default(),
        );
    }

    #[test]
    fn canonical_metadata_stays_out_of_the_legacy_primary_only_catalog() {
        let caller_file = test_file("src/Caller.java");
        let target_file = test_file("src/Target.java");
        let caller = test_unit(&caller_file, CodeUnitType::Function, "Caller.run");
        let target = test_unit(&target_file, CodeUnitType::Function, "Target.run");
        let catalog = WorkspaceUsageCatalog::from_declarations(
            vec![
                (caller.clone(), Some(test_range(0, 80, 1))),
                (target.clone(), Some(test_range(0, 80, 1))),
            ],
            &CancellationToken::default(),
        )
        .expect("the legacy catalog still builds for legacy consumers");
        let canonical = CanonicalWorkspaceUsageCatalog::from_declarations_with_all_ranges(
            vec![
                (caller, vec![test_range(0, 80, 1)]),
                (target, vec![test_range(0, 80, 1)]),
            ],
            CANONICAL_GENERATION,
            &CancellationToken::default(),
        )
        .expect("the canonical wrapper builds separately");

        assert_eq!(catalog.nodes.len(), canonical.nodes().len());
        assert_eq!(
            canonical.declaration_spans_by_node.len(),
            canonical.nodes().len()
        );
    }

    #[test]
    #[should_panic(expected = "canonical reference-edge target")]
    fn canonical_graph_target_rows_fail_closed_when_the_crosswalk_is_missing() {
        let caller_file = test_file("src/Caller.java");
        let target_file = test_file("src/Target.java");
        let caller = test_unit(&caller_file, CodeUnitType::Function, "Caller.run");
        let target = test_unit(&target_file, CodeUnitType::Function, "Target.run");
        let catalog = canonical_catalog([(caller.clone(), vec![test_range(0, 80, 1)])]);
        let rows = [canonical_row(
            &caller_file,
            test_range(100, 106, 7),
            &caller,
            &target,
            Some(ReferenceKind::MethodCall),
            UsageProof::Proven,
        )];

        let _ = reduce_canonical_reference_edges_to_workspace_usage_graph(
            catalog,
            &rows,
            &EdgeCompleteness::Complete,
            &BTreeSet::from([UsageEcosystem::Jvm]),
            &CancellationToken::default(),
        );
    }

    #[test]
    #[should_panic(expected = "canonical reference-edge source")]
    fn canonical_graph_source_rows_fail_closed_when_the_crosswalk_is_missing() {
        let caller_file = test_file("src/Caller.java");
        let target_file = test_file("src/Target.java");
        let caller = test_unit(&caller_file, CodeUnitType::Function, "Caller.run");
        let target = test_unit(&target_file, CodeUnitType::Function, "Target.run");
        let catalog = canonical_catalog([(target.clone(), vec![test_range(0, 80, 1)])]);
        let rows = [canonical_row(
            &caller_file,
            test_range(100, 106, 7),
            &caller,
            &target,
            Some(ReferenceKind::MethodCall),
            UsageProof::Proven,
        )];

        let _ = reduce_canonical_reference_edges_to_workspace_usage_graph(
            catalog,
            &rows,
            &EdgeCompleteness::Complete,
            &BTreeSet::from([UsageEcosystem::Jvm]),
            &CancellationToken::default(),
        );
    }

    #[test]
    fn canonical_field_targets_are_skipped_and_field_sources_are_inbound_only() {
        let caller_file = test_file("src/Caller.java");
        let target_file = test_file("src/Target.java");
        let field_source_file = test_file("src/FieldSource.java");
        let caller = test_unit(&caller_file, CodeUnitType::Function, "Caller.run");
        let target = test_unit(&target_file, CodeUnitType::Class, "Target");
        let field_target = test_unit(&target_file, CodeUnitType::Field, "Target.value");
        let field_source = test_unit(&field_source_file, CodeUnitType::Field, "FieldSource.value");
        let catalog = canonical_catalog([
            (caller.clone(), vec![test_range(0, 80, 1)]),
            (target.clone(), vec![test_range(0, 80, 1)]),
        ]);
        let mut rows = vec![canonical_row(
            &caller_file,
            test_range(100, 106, 7),
            &caller,
            &field_target,
            Some(ReferenceKind::FieldRead),
            UsageProof::Proven,
        )];
        rows.extend((0..=MAX_CALLSITES).map(|index| {
            canonical_row(
                &field_source_file,
                test_range(100 + index, 101 + index, 8),
                &field_source,
                &target,
                Some(ReferenceKind::FieldRead),
                UsageProof::Proven,
            )
        }));
        rows.push(canonical_row(
            &field_source_file,
            test_range(MAX_CALLSITES + 200, MAX_CALLSITES + 201, 9),
            &field_source,
            &target,
            Some(ReferenceKind::FieldRead),
            UsageProof::Unproven,
        ));

        let graph =
            complete_canonical_graph(reduce_canonical_reference_edges_to_workspace_usage_graph(
                catalog,
                &rows,
                &EdgeCompleteness::Complete,
                &BTreeSet::from([UsageEcosystem::Jvm]),
                &CancellationToken::default(),
            ));
        let target = node_index(&graph, &target);
        assert_eq!(graph.nodes.len(), 2, "fields are not rankable graph nodes");
        assert_eq!(
            graph.nodes[target].truncated_inbound,
            Some(MAX_CALLSITES + 1),
            "proven field-owned sites count toward the target cap before caller-node rejection"
        );
        assert_eq!(graph.nodes[target].unproven_inbound, 1);
        assert!(graph.edges.is_empty(), "field owners never add topology");
    }

    #[test]
    fn canonical_unproven_self_receivers_preserve_field_and_sibling_uncertainty() {
        const SOURCE: &str = "package fixture;\nclass Owner {\n    int value = helper();\n    int helper() { return sibling(); }\n    int sibling() { return 1; }\n    int recursive() { return recursive(); }\n}\n";
        let project = InlineTestProject::with_language(Language::Java)
            .file("src/Owner.java", SOURCE)
            .build();
        let file = project.file("src/Owner.java");
        let analyzer = JavaAnalyzer::new(project.project_dyn());
        let declarations = analyzer.declarations(&file);
        let declaration = |name: &str, field: bool| {
            declarations
                .iter()
                .find(|unit| {
                    unit.terminal_name() == name
                        && if field {
                            unit.is_field()
                        } else {
                            unit.is_callable()
                        }
                })
                .unwrap_or_else(|| panic!("the real Java analyzer must retain Owner.{name}"))
                .clone()
        };
        let field = declaration("value", true);
        let helper = declaration("helper", false);
        let sibling = declaration("sibling", false);
        let recursive = declaration("recursive", false);
        let catalog = CanonicalWorkspaceUsageCatalog::build_with_cancellation(
            &analyzer,
            &CancellationToken::default(),
        )
        .expect("the real stable analyzer snapshot must build a canonical catalog");
        let generation = catalog.generation;
        let self_receiver_row =
            |marker: &str, token: &str, enclosing: &CodeUnit, target: &CodeUnit| {
                let marker_start = SOURCE
                    .find(marker)
                    .unwrap_or_else(|| panic!("the fixture must contain {marker}"));
                let start = marker_start
                    + marker
                        .find(token)
                        .unwrap_or_else(|| panic!("{marker} must contain {token}"));
                let mut row = canonical_row(
                    &file,
                    test_range(start, start + token.len(), 1),
                    enclosing,
                    target,
                    Some(ReferenceKind::MethodCall),
                    UsageProof::Unproven,
                );
                row.usage_kind = UsageHitKind::SelfReceiver;
                row.generation = generation;
                row
            };
        let rows = [
            self_receiver_row("value = helper()", "helper", &field, &helper),
            self_receiver_row("return sibling()", "sibling", &helper, &sibling),
            self_receiver_row("return recursive()", "recursive", &recursive, &recursive),
        ];

        let graph = complete_canonical_graph(
            reduce_canonical_reference_edge_rows_to_workspace_usage_graph(
                catalog,
                &rows,
                generation,
                &EdgeCompleteness::Complete,
                &BTreeSet::from([UsageEcosystem::Jvm]),
                &CancellationToken::default(),
            ),
        );
        let helper = node_index(&graph, &helper);
        let sibling = node_index(&graph, &sibling);
        let recursive = node_index(&graph, &recursive);
        assert_eq!(
            graph.nodes[helper].unproven_inbound, 1,
            "an implicit call owned by a field remains target-local uncertainty"
        );
        assert_eq!(
            graph.nodes[sibling].unproven_inbound, 1,
            "a non-recursive same-owner sibling call remains target-local uncertainty"
        );
        assert_eq!(
            graph.nodes[recursive].unproven_inbound, 0,
            "a truly recursive grouped self edge remains excluded"
        );
        assert!(
            graph
                .nodes
                .iter()
                .all(|node| node.truncated_inbound.is_none()),
            "unproven self-receivers never consume the proven callsite cap"
        );
        assert!(
            graph.edges.is_empty(),
            "unproven self-receivers never add ranking topology"
        );
    }

    #[test]
    fn canonical_grouped_self_and_every_definition_span_are_excluded() {
        let part_a_file = test_file("src/Widget.PartA.cs");
        let part_b_file = test_file("src/Widget.PartB.cs");
        let caller_file = test_file("src/Caller.cs");
        let target_a = test_unit(&part_a_file, CodeUnitType::Class, "Widget");
        let target_b = test_unit(&part_b_file, CodeUnitType::Class, "Widget");
        let target_member = test_unit(&part_b_file, CodeUnitType::Function, "Widget.inside");
        let caller = test_unit(&caller_file, CodeUnitType::Function, "Caller.run");
        let catalog = canonical_catalog([
            (
                target_a.clone(),
                vec![test_range(10, 100, 1), test_range(110, 120, 10)],
            ),
            (
                target_b.clone(),
                vec![test_range(200, 300, 20), test_range(320, 330, 30)],
            ),
            (target_member.clone(), vec![test_range(315, 335, 29)]),
            (caller.clone(), vec![test_range(0, 80, 1)]),
        ]);
        let target_catalog_index = catalog
            .index_for_id(&target_a.declaration_id())
            .expect("the grouped target belongs to the canonical catalog");
        assert_eq!(catalog.declaration_spans(target_catalog_index).len(), 4);
        let rows = vec![
            canonical_row(
                &part_b_file,
                test_range(400, 406, 40),
                &target_b,
                &target_a,
                Some(ReferenceKind::FieldRead),
                UsageProof::Proven,
            ),
            canonical_row(
                &part_b_file,
                test_range(322, 328, 30),
                &target_member,
                &target_a,
                Some(ReferenceKind::FieldRead),
                UsageProof::Proven,
            ),
            canonical_row(
                &part_b_file,
                test_range(323, 329, 30),
                &target_member,
                &target_a,
                Some(ReferenceKind::FieldRead),
                UsageProof::Unproven,
            ),
            canonical_row(
                &caller_file,
                test_range(100, 106, 7),
                &caller,
                &target_a,
                Some(ReferenceKind::FieldRead),
                UsageProof::Proven,
            ),
        ];
        let selected = BTreeSet::from([UsageEcosystem::CSharp]);
        let graph =
            complete_canonical_graph(reduce_canonical_reference_edges_to_workspace_usage_graph(
                catalog,
                &rows,
                &EdgeCompleteness::Complete,
                &selected,
                &CancellationToken::default(),
            ));
        let target = node_index(&graph, &target_a);
        let caller = node_index(&graph, &caller);
        let target_member = node_index(&graph, &target_member);
        assert_eq!(graph.nodes[target].declaration_ids.len(), 2);
        assert_eq!(graph.nodes[target].unproven_inbound, 0);
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.from == caller && edge.to == target)
        );
        assert!(
            graph
                .edges
                .iter()
                .all(|edge| !(edge.from == target_member && edge.to == target)),
            "a site inside a grouped declaration's non-primary range is not graph topology"
        );
        assert!(
            graph.edges.iter().all(|edge| edge.from != target),
            "two declarations grouped into one node form a self edge even when their IDs differ"
        );
    }
}
