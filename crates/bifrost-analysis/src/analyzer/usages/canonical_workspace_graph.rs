//! Canonical selected-resolution workspace graph projection.
//!
//! The legacy workspace graph remains in the parent module. This module owns
//! the selected canonical path so its eventual cutover is a module operation.

use crate::analyzer::resolution::reference_vocabulary::WithheldReference;
use crate::analyzer::store::resolution_operation::graph_stage::{
    GraphBuildSelectionUnavailable, GraphSkippedCallers, certify_graph_callers,
};
use std::collections::{BTreeMap, BTreeSet};

use super::super::inverted_edges::MAX_CALLSITES;
use super::super::{ReferenceKind, UsageHitKind, UsageHitSurface, UsageProof};
use super::*;
#[cfg(any(test, feature = "test-support"))]
use crate::analyzer::resolution::{
    BindingFragmentId, FactReferenceEdgeCatalog, FactReferenceEdgeDeclarationDomain,
    FactReferenceEdgeDomainStatus, FactResolutionSource, SelectedFactResolutionSnapshot,
    stage_selected_reference_edge_batches, validate_selected_reference_edge_coverage,
};
use crate::analyzer::resolution::{ResolutionBatchMetrics, ResolutionCompletion};
use crate::analyzer::store::resolution_operation::SelectedResolutionOperationOutcome;
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
#[doc(hidden)]
pub struct CanonicalWorkspaceUsageCatalog {
    #[doc(hidden)]
    pub catalog: WorkspaceUsageCatalog,
    #[doc(hidden)]
    pub declaration_spans_by_node: Vec<Vec<(ProjectFile, Range)>>,
    #[doc(hidden)]
    pub generation: u64,
}

impl CanonicalWorkspaceUsageCatalog {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn build_with_cancellation(
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

    #[doc(hidden)]
    pub fn from_declarations_with_all_ranges(
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
    #[doc(hidden)]
    pub fn nodes(&self) -> &[WorkspaceUsageNode] {
        &self.catalog.nodes
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn index_for_id(&self, id: &DeclarationId) -> Option<usize> {
        self.catalog.index_for_id(id)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn declaration_spans(&self, index: usize) -> &[(ProjectFile, Range)] {
        &self.declaration_spans_by_node[index]
    }
}

/// The result of reducing one complete generation of canonical forward rows.
///
/// `Incomplete` retains the sound positive inventory for the current request,
/// but callers must not cache or interpret absence from that graph as proof.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub enum CanonicalWorkspaceUsageGraphBuildOutcome {
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
#[doc(hidden)]
pub struct CanonicalWorkspaceUsageProjectedEdge {
    /// Proven self-receiver dependencies, included only by opted-in public graphs.
    /// These sites do not contribute to external usage or ranking counters.
    pub same_owner_sites: Vec<(ProjectFile, usize)>,
    /// Unproven self-receiver sites, drawn only by opted-in public graphs.
    pub unproven_same_owner_sites: Vec<(ProjectFile, usize)>,
    /// Possible callers excluded from ranking counts. May overlap `sites` when
    /// a line contains both proven and unproven references.
    pub unproven_sites: Vec<(ProjectFile, usize)>,
    #[doc(hidden)]
    pub from: usize,
    #[doc(hidden)]
    pub to: usize,
    #[doc(hidden)]
    pub counts: UsageReferenceCounts,
    #[doc(hidden)]
    pub sites: Vec<(ProjectFile, usize)>,
}

type CanonicalProjectedEdgesByNodePair =
    BTreeMap<(usize, usize), (UsageReferenceCounts, BTreeSet<(ProjectFile, usize)>)>;

#[doc(hidden)]
pub struct CanonicalWorkspaceUsageGraphProjection {
    #[doc(hidden)]
    pub nodes: Vec<WorkspaceUsageNode>,
    #[doc(hidden)]
    pub edges: Vec<CanonicalWorkspaceUsageProjectedEdge>,
    /// Dependencies drawn only when the public graph opts into same-owner sites.
    pub same_owner_edges: Vec<CanonicalWorkspaceUsageProjectedEdge>,
    #[doc(hidden)]
    pub raw_proven_inbound: Vec<usize>,
    #[doc(hidden)]
    pub admitted_callers: HashSet<ProjectFile>,
    #[doc(hidden)]
    pub unresolved_names: Option<BTreeSet<String>>,
    #[doc(hidden)]
    pub withheld_references: Vec<WithheldReference>,
    #[doc(hidden)]
    pub forward_completeness: EdgeCompleteness,
    #[doc(hidden)]
    pub kind_projection_complete: bool,
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub resolved_ecosystems: Vec<UsageEcosystem>,
}

#[cfg(any(test, feature = "test-support"))]
impl CanonicalWorkspaceUsageGraphProjection {
    #[doc(hidden)]
    pub fn into_workspace_graph(
        self,
        cancellation: &CancellationToken,
    ) -> Option<WorkspaceUsageGraph> {
        projected_graph_into_workspace_graph(
            self.nodes,
            self.edges,
            cancellation,
            #[cfg(any(test, feature = "test-support"))]
            self.resolved_ecosystems,
        )
    }
}

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn projected_edges_into_ranking_edges(
    nodes: &[WorkspaceUsageNode],
    edges: Vec<CanonicalWorkspaceUsageProjectedEdge>,
    cancellation: &CancellationToken,
) -> Option<Vec<WorkspaceUsageEdge>> {
    let mut ranking_edges = Vec::with_capacity(edges.len());
    for edge in edges {
        if cancellation.is_cancelled() {
            return None;
        }
        if nodes[edge.to].truncated_inbound.is_some() || edge.sites.is_empty() {
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

#[cfg(any(test, feature = "test-support"))]
fn projected_graph_into_workspace_graph(
    nodes: Vec<WorkspaceUsageNode>,
    edges: Vec<CanonicalWorkspaceUsageProjectedEdge>,
    cancellation: &CancellationToken,
    #[cfg(any(test, feature = "test-support"))] resolved_ecosystems: Vec<UsageEcosystem>,
) -> Option<WorkspaceUsageGraph> {
    let edges = projected_edges_into_ranking_edges(&nodes, edges, cancellation)?;
    Some(WorkspaceUsageGraph {
        nodes,
        edges,
        #[cfg(any(test, feature = "test-support"))]
        resolved_ecosystems,
    })
}

#[doc(hidden)]
pub enum CanonicalWorkspaceUsageGraphProjectionOutcome {
    Complete(CanonicalWorkspaceUsageGraphProjection),
    Incomplete(CanonicalWorkspaceUsageGraphProjection),
    Cancelled,
}

#[doc(hidden)]
pub struct CanonicalWorkspaceUsageGraphAccumulator {
    nodes: Vec<WorkspaceUsageNode>,
    indices_by_id: HashMap<DeclarationId, usize>,
    declaration_spans_by_node: Vec<Vec<(ProjectFile, Range)>>,
    generation: u64,
    selected_ecosystems: BTreeSet<UsageEcosystem>,
    site_file_ids: HashMap<ProjectFile, usize>,
    site_files: Vec<ProjectFile>,
    proven_callsites: HashSet<(usize, usize, usize)>,
    graph_callsites: HashSet<(usize, usize, usize)>,
    unproven_sites: HashSet<(usize, usize, usize)>,
    proven_non_graph_sites: HashSet<(usize, usize, usize)>,
    /// The names this build's unresolved forward bindings spell, or `None`
    /// when one of them has no identifier this route could read. Bounded by
    /// the workspace's distinct identifiers and discarded with the graph.
    unresolved_names: Option<BTreeSet<String>>,
    same_owner_by_line: HashSet<(usize, usize, usize, usize)>,
    unproven_same_owner_by_line: HashSet<(usize, usize, usize, usize)>,
    unproven_by_line: HashSet<(usize, usize, usize, usize)>,
    withheld_references: Vec<WithheldReference>,
    strongest_kind_by_line: HashMap<(usize, usize, usize, usize), UsageReferenceKind>,
    kind_projection_complete: bool,
    admitted_callers: HashSet<ProjectFile>,
}

impl CanonicalWorkspaceUsageGraphAccumulator {
    #[doc(hidden)]
    pub fn new(
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
            graph_callsites: HashSet::default(),
            unproven_sites: HashSet::default(),
            proven_non_graph_sites: HashSet::default(),
            unresolved_names: Some(BTreeSet::new()),
            same_owner_by_line: HashSet::default(),
            unproven_same_owner_by_line: HashSet::default(),
            unproven_by_line: HashSet::default(),
            withheld_references: Vec::new(),
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
    #[doc(hidden)]
    pub fn stage_rows(
        &mut self,
        rows: &[ReferenceEdgeRow],
        cancellation: &CancellationToken,
    ) -> bool {
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
            if source == Some(target) {
                continue;
            }

            let external_usage = row.included_in(UsageHitSurface::ExternalUsages);
            let ambiguous_candidate =
                row.ambiguous_candidate && row.proof == UsageProof::Unproven && external_usage;
            let unproven_self_receiver =
                row.proof == UsageProof::Unproven && row.usage_kind == UsageHitKind::SelfReceiver;
            let proven_self_receiver =
                row.proof == UsageProof::Proven && row.usage_kind == UsageHitKind::SelfReceiver;
            if !external_usage && !unproven_self_receiver && !proven_self_receiver {
                continue;
            }

            let mut site_file = None;
            if row.site.enclosing.is_some()
                && ((row.proof == UsageProof::Proven && external_usage) || ambiguous_candidate)
            {
                // Preserve the legacy cap boundary: a proven external target
                // site and each exact ambiguous candidate count before
                // definition-overlap and caller-node exclusions.
                let file = self.site_file_id(&row.site.file);
                let callsite = (target, file, row.site.range.start_byte);
                self.graph_callsites.insert(callsite);
                if row.proof == UsageProof::Proven {
                    self.proven_callsites.insert(callsite);
                }
                site_file = Some(file);
            }

            let target_definition_spans = &self.declaration_spans_by_node[target];
            // Usage-surface filtering is already complete. Check only overlap:
            // graph admission also excludes the ownerless sites retained here.
            if row.overlaps_target_definition_spans(target_definition_spans) {
                continue;
            }
            if proven_self_receiver {
                if let Some(source) = source
                    && self.nodes[source].key.ecosystem == self.nodes[target].key.ecosystem
                {
                    // Keep opt-in dependency sites apart from ranking's external
                    // usage counters. Public caps count the requested line sites.
                    let file = self.site_file_id(&row.site.file);
                    self.same_owner_by_line.insert((
                        source,
                        target,
                        file,
                        row.site.range.start_line,
                    ));
                }
                continue;
            }
            if row.proof == UsageProof::Unproven {
                let file = self.site_file_id(&row.site.file);
                self.unproven_sites
                    .insert((target, file, row.site.range.start_byte));
                if let Some(source) = source
                    && self.nodes[source].key.ecosystem == self.nodes[target].key.ecosystem
                {
                    let sites = if unproven_self_receiver {
                        &mut self.unproven_same_owner_by_line
                    } else {
                        &mut self.unproven_by_line
                    };
                    sites.insert((source, target, file, row.site.range.start_line));
                }
                if !ambiguous_candidate {
                    continue;
                }
            }

            let Some(source) = source else {
                if row.proof == UsageProof::Proven && external_usage {
                    let file = self.site_file_id(&row.site.file);
                    self.proven_non_graph_sites
                        .insert((target, file, row.site.range.start_byte));
                }
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

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn finish(
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

    #[doc(hidden)]
    pub fn finish_projection(
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
        for (target, _, _) in self.proven_callsites.iter().copied() {
            if cancellation.is_cancelled() {
                return CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled;
            }
            proven_inbound[target] = proven_inbound[target].saturating_add(1);
        }
        let mut graph_inbound = vec![0_usize; self.nodes.len()];
        for (target, _, _) in self.graph_callsites {
            if cancellation.is_cancelled() {
                return CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled;
            }
            graph_inbound[target] = graph_inbound[target].saturating_add(1);
        }
        for (target, file, _) in self.proven_non_graph_sites {
            if cancellation.is_cancelled() {
                return CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled;
            }
            let count = self.nodes[target]
                .proven_non_graph_inbound_by_file
                .entry(self.site_files[file].clone())
                .or_default();
            *count = count
                .checked_add(1)
                .expect("non-graph inbound count fits usize");
        }
        for (target, _, _) in self.unproven_sites {
            if cancellation.is_cancelled() {
                return CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled;
            }
            self.nodes[target].unproven_inbound =
                self.nodes[target].unproven_inbound.saturating_add(1);
        }
        for (target, total) in graph_inbound.into_iter().enumerate() {
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
        let mut unproven_by_edge: BTreeMap<_, BTreeSet<_>> = BTreeMap::new();
        for (source, target, file, line) in self.unproven_by_line {
            if cancellation.is_cancelled() {
                return CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled;
            }
            projected_by_edge.entry((source, target)).or_default();
            unproven_by_edge
                .entry((source, target))
                .or_default()
                .insert((self.site_files[file].clone(), line));
        }
        let mut unproven_same_owner_by_edge: BTreeMap<_, BTreeSet<_>> = BTreeMap::new();
        for (source, target, file, line) in self.unproven_same_owner_by_line {
            if cancellation.is_cancelled() {
                return CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled;
            }
            projected_by_edge.entry((source, target)).or_default();
            unproven_same_owner_by_edge
                .entry((source, target))
                .or_default()
                .insert((self.site_files[file].clone(), line));
        }
        let mut same_owner_by_edge: BTreeMap<_, BTreeSet<_>> = BTreeMap::new();
        for (source, target, file, line) in self.same_owner_by_line {
            if cancellation.is_cancelled() {
                return CanonicalWorkspaceUsageGraphProjectionOutcome::Cancelled;
            }
            projected_by_edge.entry((source, target)).or_default();
            same_owner_by_edge
                .entry((source, target))
                .or_default()
                .insert((self.site_files[file].clone(), line));
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
                unproven_same_owner_sites: unproven_same_owner_by_edge
                    .remove(&(from, to))
                    .unwrap_or_default()
                    .into_iter()
                    .collect(),
                same_owner_sites: same_owner_by_edge
                    .remove(&(from, to))
                    .unwrap_or_default()
                    .into_iter()
                    .collect(),
                unproven_sites: unproven_by_edge
                    .remove(&(from, to))
                    .unwrap_or_default()
                    .into_iter()
                    .collect(),
            });
        }

        #[cfg(any(test, feature = "test-support"))]
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
        let (same_owner_edges, edges) = edges
            .into_iter()
            .partition(|edge| edge.sites.is_empty() && edge.unproven_sites.is_empty());
        let projection = CanonicalWorkspaceUsageGraphProjection {
            nodes: self.nodes,
            edges,
            same_owner_edges,
            raw_proven_inbound: proven_inbound,
            admitted_callers: self.admitted_callers,
            unresolved_names: self.unresolved_names,
            withheld_references: self.withheld_references,
            forward_completeness: forward_completeness.clone(),
            kind_projection_complete: self.kind_projection_complete,
            #[cfg(any(test, feature = "test-support"))]
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
/// the incumbent `brokk_bifrost_tools::searchtools::UsageGraphResult`, while the ranking
/// adapter consumes the same nodes and edges without the site inventory.
///
/// Nodes also retain proven external sites whose caller is not a graph node,
/// counted per file after deduplication by (file, byte). These counters do not
/// draw edges or enter the graph callsite cap, truncated_inbound, or
/// raw_proven_inbound. The legacy cap accounting of sites with an enclosing
/// non-graph declaration remains unchanged.
#[doc(hidden)]
pub struct SelectedWorkspaceUsageGraphProjection {
    #[doc(hidden)]
    pub nodes: Vec<WorkspaceUsageNode>,
    #[doc(hidden)]
    pub edges: Vec<CanonicalWorkspaceUsageProjectedEdge>,
    /// Dependencies drawn only when the public graph opts into same-owner sites.
    pub same_owner_edges: Vec<CanonicalWorkspaceUsageProjectedEdge>,
    /// Exact distinct (target, source file, byte offset) counts, including
    /// below-cap totals. Aligned with nodes, never inferred from line sites.
    #[doc(hidden)]
    pub raw_proven_inbound: Vec<usize>,
    /// Includes admitted empty files. Dependency declaration files are not
    /// callers unless the source operation independently admitted them.
    #[doc(hidden)]
    pub admitted_callers: HashSet<ProjectFile>,
    #[doc(hidden)]
    pub skipped_callers: GraphSkippedCallers,
    #[doc(hidden)]
    pub build_selection_unavailable: Option<GraphBuildSelectionUnavailable>,
    /// Domain failures do not withdraw admitted source-inventory callers.
    pub domain_discovery_failures:
        Vec<crate::analyzer::store::resolution_operation::graph_stage::GraphDomainDiscoveryFailure>,
    /// The terminal names of every declaration an inbound edge this build
    /// did not draw may reach, or `None` when one such edge has no name the
    /// route could read. See `FactReferenceEdgeBatch::unresolved_names`.
    ///
    /// A forward gap can only add an inbound edge, never remove one, and only
    /// to a declaration one of these names reaches. A consumer that proves a
    /// declaration unused abstains on those and keeps its proof for the rest;
    /// `None` leaves it no attribution, and it abstains on the whole pass.
    #[doc(hidden)]
    pub unresolved_names: Option<BTreeSet<String>>,
    #[doc(hidden)]
    pub withheld_references: Vec<WithheldReference>,
    #[doc(hidden)]
    pub forward_completeness: EdgeCompleteness,
    #[doc(hidden)]
    pub kind_projection_complete: bool,
    #[doc(hidden)]
    pub generation: u64,
    #[doc(hidden)]
    pub reference_count: usize,
    #[doc(hidden)]
    pub projected_edge_count: usize,
    #[doc(hidden)]
    pub batch_count: usize,
    #[doc(hidden)]
    pub root_binding_metrics: ResolutionBatchMetrics,
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub resolved_ecosystems: Vec<UsageEcosystem>,
}

impl SelectedWorkspaceUsageGraphProjection {
    #[doc(hidden)]
    pub fn raw_proven_inbound(&self) -> &[usize] {
        &self.raw_proven_inbound
    }

    #[doc(hidden)]
    pub fn certify_callers(&self, requested: &HashSet<ProjectFile>) {
        certify_graph_callers(requested, &self.admitted_callers, &self.skipped_callers);
    }

    #[doc(hidden)]
    pub fn admitted_callers(&self) -> &HashSet<ProjectFile> {
        &self.admitted_callers
    }

    #[cfg(any(test, feature = "test-support"))]
    fn into_ranking_parts(
        self,
        cancellation: &CancellationToken,
    ) -> Option<(WorkspaceUsageGraph, u64, usize, usize, usize)> {
        assert_eq!(self.raw_proven_inbound().len(), self.nodes.len());
        let graph = projected_graph_into_workspace_graph(
            self.nodes,
            self.edges,
            cancellation,
            #[cfg(any(test, feature = "test-support"))]
            self.resolved_ecosystems,
        )?;
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
#[doc(hidden)]
pub enum SelectedWorkspaceUsageGraphProjectionOutcome {
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
#[doc(hidden)]
pub struct CanonicalWorkspaceUsageDeclaration<'a> {
    #[doc(hidden)]
    pub key: &'a WorkspaceUsageNodeKey,
    #[doc(hidden)]
    pub primary: &'a CodeUnit,
    #[doc(hidden)]
    pub primary_range: Option<Range>,
}

/// One contribution with its original evidence and a new endpoint numbering.
#[doc(hidden)]
pub struct CanonicalWorkspaceUsageRemappedProjection<'a> {
    #[doc(hidden)]
    pub projection: &'a SelectedWorkspaceUsageGraphProjection,
    #[doc(hidden)]
    pub node_indices: Vec<usize>,
}

#[doc(hidden)]
pub struct CanonicalWorkspaceUsageRemappedEdge<'a> {
    #[doc(hidden)]
    pub from: usize,
    #[doc(hidden)]
    pub to: usize,
    #[doc(hidden)]
    pub counts: UsageReferenceCounts,
    #[doc(hidden)]
    pub sites: &'a [(ProjectFile, usize)],
    pub same_owner_sites: &'a [(ProjectFile, usize)],
    pub unproven_same_owner_sites: &'a [(ProjectFile, usize)],
    pub unproven_sites: &'a [(ProjectFile, usize)],
}

impl CanonicalWorkspaceUsageRemappedProjection<'_> {
    #[doc(hidden)]
    pub fn edges(&self) -> impl Iterator<Item = CanonicalWorkspaceUsageRemappedEdge<'_>> {
        self.projection
            .edges
            .iter()
            .chain(&self.projection.same_owner_edges)
            .map(|edge| CanonicalWorkspaceUsageRemappedEdge {
                from: self.node_indices[edge.from],
                to: self.node_indices[edge.to],
                counts: edge.counts,
                sites: &edge.sites,
                same_owner_sites: &edge.same_owner_sites,
                unproven_same_owner_sites: &edge.unproven_same_owner_sites,
                unproven_sites: &edge.unproven_sites,
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
#[doc(hidden)]
pub struct CanonicalWorkspaceUsageNodeRemapping<'a> {
    #[doc(hidden)]
    pub generation: u64,
    #[doc(hidden)]
    pub declarations: Vec<CanonicalWorkspaceUsageDeclaration<'a>>,
    #[doc(hidden)]
    pub initial_nodes: &'a [WorkspaceUsageNode],
    #[doc(hidden)]
    pub initial_node_indices: Vec<usize>,
    #[doc(hidden)]
    pub projections: Vec<CanonicalWorkspaceUsageRemappedProjection<'a>>,
}

#[doc(hidden)]
pub enum CanonicalWorkspaceUsageNodeRemappingOutcome<'a> {
    Ready(CanonicalWorkspaceUsageNodeRemapping<'a>),
    Cancelled,
    Stale { expected: u64, actual: u64 },
}

/// Share exact DeclarationId endpoint numbering without projecting through
/// names or dropping dependency declarations absent from the initial catalog.
/// All inputs are borrowed and all index tables remain private until success.
/// The caller supplies the initial catalog's generation even when it is empty;
/// operation authority must still be revalidated before publishing a graph.
#[doc(hidden)]
pub fn remap_workspace_usage_projection_nodes<'a>(
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
        for edge in projection.edges.iter().chain(&projection.same_owner_edges) {
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
#[doc(hidden)]
pub fn aggregate_disjoint_workspace_usage_projections(
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
    let mut accounted_callers = HashSet::default();
    let mut unresolved_names = Some(BTreeSet::new());
    let mut withheld_references = Vec::new();
    for projection in projections {
        for reference in &projection.withheld_references {
            if cancellation.is_cancelled() {
                return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
            }
            withheld_references.push(reference.clone());
        }
        for file in projection
            .admitted_callers()
            .iter()
            .chain(projection.skipped_callers.keys())
        {
            if cancellation.is_cancelled() {
                return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
            }
            if !accounted_callers.insert(file.clone()) {
                overlapping.insert(file.clone());
            }
        }
        admitted_callers.extend(projection.admitted_callers().iter().cloned());
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
            implements: None,
            implicit_callers: None,
            key: declaration.key.clone(),
            primary: declaration.primary.clone(),
            primary_range: declaration.primary_range,
            declaration_files: Vec::new(),
            declaration_ids: Vec::new(),
            truncated_inbound: None,
            unproven_inbound: 0,
            proven_non_graph_inbound_by_file: BTreeMap::new(),
        });
    }
    let mut raw_proven_inbound = vec![0_usize; nodes.len()];
    let mut projected_by_edge = CanonicalProjectedEdgesByNodePair::new();
    let mut unproven_by_edge: BTreeMap<_, BTreeSet<_>> = BTreeMap::new();
    let mut unproven_same_owner_by_edge: BTreeMap<_, BTreeSet<_>> = BTreeMap::new();
    let mut same_owner_by_edge: BTreeMap<_, BTreeSet<_>> = BTreeMap::new();
    let mut reasons = Vec::new();
    let mut kind_projection_complete = true;
    let mut reference_count = 0_usize;
    let mut projected_edge_count = 0_usize;
    let mut batch_count = 0_usize;
    let mut root_binding_metrics = ResolutionBatchMetrics::default();
    #[cfg(any(test, feature = "test-support"))]
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
        #[cfg(any(test, feature = "test-support"))]
        resolved_ecosystems.extend(projection.resolved_ecosystems.iter().copied());
        for (local, &global) in contribution.node_indices.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
            }
            let source = &projection.nodes[local];
            if let Some(member) = &source.implements {
                nodes[global].implements = Some(member.clone());
            }
            if let Some(implicit) = &source.implicit_callers {
                nodes[global].implicit_callers = Some(implicit.clone());
            }
            raw_proven_inbound[global] = raw_proven_inbound[global]
                .checked_add(projection.raw_proven_inbound()[local])
                .expect("raw inbound count overflow");
            let node = &mut nodes[global];
            for (file, count) in &source.proven_non_graph_inbound_by_file {
                let total = node
                    .proven_non_graph_inbound_by_file
                    .entry(file.clone())
                    .or_default();
                *total = total
                    .checked_add(*count)
                    .expect("non-graph inbound count fits usize");
            }
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
            unproven_same_owner_by_edge
                .entry((edge.from, edge.to))
                .or_default()
                .extend(edge.unproven_same_owner_sites.iter().cloned());
            same_owner_by_edge
                .entry((edge.from, edge.to))
                .or_default()
                .extend(edge.same_owner_sites.iter().cloned());
            unproven_by_edge
                .entry((edge.from, edge.to))
                .or_default()
                .extend(edge.unproven_sites.iter().cloned());
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
            unproven_same_owner_sites: unproven_same_owner_by_edge
                .remove(&(from, to))
                .unwrap_or_default()
                .into_iter()
                .collect(),
            same_owner_sites: same_owner_by_edge
                .remove(&(from, to))
                .unwrap_or_default()
                .into_iter()
                .collect(),
            unproven_sites: unproven_by_edge
                .remove(&(from, to))
                .unwrap_or_default()
                .into_iter()
                .collect(),
        });
    }
    let forward_completeness = if reasons.is_empty() {
        EdgeCompleteness::Complete
    } else {
        EdgeCompleteness::Incomplete { reasons }
    };
    let complete = !projections.iter().any(|projection| {
        projection.build_selection_unavailable.is_some()
            || !projection.domain_discovery_failures.is_empty()
            || projection
                .skipped_callers
                .values()
                .any(|reason| reason.opens_incompleteness())
    }) && kind_projection_complete
        && [
            EdgeAxis::ForwardProjection,
            EdgeAxis::OwnerClassification,
            EdgeAxis::KindClassification,
        ]
        .into_iter()
        .all(|axis| forward_completeness.covers(axis));
    let (same_owner_edges, edges) = edges
        .into_iter()
        .partition(|edge| edge.sites.is_empty() && edge.unproven_sites.is_empty());
    let projection = SelectedWorkspaceUsageGraphProjection {
        nodes,
        edges,
        same_owner_edges,
        raw_proven_inbound,
        admitted_callers,
        build_selection_unavailable: projections
            .iter()
            .find_map(|projection| projection.build_selection_unavailable.clone()),
        domain_discovery_failures: projections
            .iter()
            .flat_map(|projection| projection.domain_discovery_failures.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        skipped_callers: projections
            .iter()
            .flat_map(|projection| projection.skipped_callers.clone())
            .collect(),
        unresolved_names,
        withheld_references,
        forward_completeness,
        kind_projection_complete,
        generation: expected_generation,
        reference_count,
        projected_edge_count,
        batch_count,
        root_binding_metrics,
        #[cfg(any(test, feature = "test-support"))]
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
#[doc(hidden)]
pub fn merge_workspace_usage_graph_projections(
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
            implements: None,
            implicit_callers: None,
            key: declaration.key.clone(),
            primary: declaration.primary.clone(),
            primary_range: declaration.primary_range,
            declaration_files: Vec::new(),
            declaration_ids: Vec::new(),
            truncated_inbound: None,
            unproven_inbound: 0,
            proven_non_graph_inbound_by_file: BTreeMap::new(),
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
        if source.implements.is_some() {
            node.implements = source.implements.clone();
        }
        if source.implicit_callers.is_some() {
            node.implicit_callers = source.implicit_callers.clone();
        }
        node.declaration_files
            .extend(source.declaration_files.iter().cloned());
        node.declaration_ids
            .extend(source.declaration_ids.iter().cloned());
        node.truncated_inbound = node.truncated_inbound.max(source.truncated_inbound);
        for (file, count) in &source.proven_non_graph_inbound_by_file {
            let total = node
                .proven_non_graph_inbound_by_file
                .entry(file.clone())
                .or_default();
            *total = total
                .checked_add(*count)
                .expect("non-graph inbound count fits usize");
        }
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
        if edge.sites.is_empty() {
            continue;
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
    #[cfg(any(test, feature = "test-support"))]
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
        #[cfg(any(test, feature = "test-support"))]
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
#[doc(hidden)]
pub struct NativeWorkspaceUsageGraphAccumulator(
    CanonicalWorkspaceUsageGraphAccumulator,
    GraphSkippedCallers,
);

impl NativeWorkspaceUsageGraphAccumulator {
    #[doc(hidden)]
    pub fn new(
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
        Some(Self(
            CanonicalWorkspaceUsageGraphAccumulator::new(
                catalog,
                BTreeSet::from([ecosystem]),
                admitted,
            ),
            GraphSkippedCallers::new(),
        ))
    }

    #[doc(hidden)]
    pub fn record_skipped_callers(&mut self, skipped: GraphSkippedCallers) {
        assert!(
            skipped
                .keys()
                .all(|file| !self.0.admitted_callers.contains(file))
        );
        // A skipped caller with missing authority can reference any name. Its
        // absence cannot support a per-declaration proof of zero inbound sites.
        if skipped.values().any(|reason| reason.opens_incompleteness()) {
            self.0.unresolved_names = None;
        }
        self.1 = skipped;
    }

    #[doc(hidden)]
    pub fn stage(&mut self, rows: &[ReferenceEdgeRow], cancellation: &CancellationToken) -> bool {
        self.0.stage_rows(rows, cancellation)
    }

    /// Retain the possible caller/callee pairs for this projection's lifetime.
    #[doc(hidden)]
    pub fn note_withheld_references(
        &mut self,
        references: &[WithheldReference],
        cancellation: &CancellationToken,
    ) -> bool {
        for reference in references {
            if cancellation.is_cancelled() {
                return false;
            }
            self.0.withheld_references.push(reference.clone());
        }
        true
    }

    /// Record the names this build's unresolved forward bindings spell.
    /// `None` means one of them had no identifier the route could read, and
    /// the projection then offers no per-declaration attribution at all.
    #[doc(hidden)]
    pub fn note_unresolved_names(
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

    #[doc(hidden)]
    pub fn finish(
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
            same_owner_edges: projection.same_owner_edges,
            raw_proven_inbound: projection.raw_proven_inbound,
            admitted_callers: projection.admitted_callers,
            skipped_callers: self.1,
            build_selection_unavailable: None,
            domain_discovery_failures: Vec::new(),
            unresolved_names: projection.unresolved_names,
            withheld_references: projection.withheld_references,
            forward_completeness: projection.forward_completeness,
            kind_projection_complete: projection.kind_projection_complete,
            generation,
            reference_count: summary.reference_count(),
            projected_edge_count,
            batch_count: summary.batch_count(),
            root_binding_metrics: summary.root_binding_metrics(),
            #[cfg(any(test, feature = "test-support"))]
            resolved_ecosystems: projection.resolved_ecosystems,
        };
        if complete
            && !projection
                .skipped_callers
                .values()
                .any(|reason| reason.opens_incompleteness())
        {
            SelectedWorkspaceUsageGraphProjectionOutcome::Complete(projection)
        } else {
            SelectedWorkspaceUsageGraphProjectionOutcome::Incomplete(projection)
        }
    }
}

/// Query-owned native graph collection shared by language providers. Language
/// rules classify rows before submission; this builder owns catalog growth,
/// incompleteness, revalidation and the canonical accumulator.
#[doc(hidden)]
pub struct NativeWorkspaceGraphBuilder {
    declarations: Vec<(CodeUnit, Vec<Range>)>,
    rooted_declarations: HashSet<CodeUnit>,
    rows: Vec<ReferenceEdgeRow>,
    unresolved_names: BTreeSet<String>,
    unresolved_names_complete: bool,
    withheld_references: Vec<WithheldReference>,
    reasons: Vec<EdgeIncompleteReason>,
    reference_count: usize,
    batch_count: usize,
    generation: u64,
}

impl NativeWorkspaceGraphBuilder {
    pub fn new(
        analyzer: &dyn IAnalyzer,
        admitted_callers: &HashSet<ProjectFile>,
        cancellation: &CancellationToken,
    ) -> Option<Self> {
        let mut declarations = Vec::new();
        for file in admitted_callers {
            if cancellation.is_cancelled() {
                return None;
            }
            let catalog = WorkspaceUsageCatalog::build_for_files_with_cancellation(
                analyzer,
                std::slice::from_ref(file),
                cancellation,
            )?;
            declarations.extend(catalog.nodes.into_iter().map(|node| node.primary));
        }
        let mut declarations_with_ranges = Vec::new();
        for unit in declarations {
            if cancellation.is_cancelled() {
                return None;
            }
            declarations_with_ranges.push((unit.clone(), analyzer.ranges(&unit)));
        }
        let declarations = declarations_with_ranges;

        let rooted_declarations = declarations.iter().map(|(unit, _)| unit.clone()).collect();
        Some(Self {
            declarations,
            rooted_declarations,
            rows: Vec::new(),
            unresolved_names: BTreeSet::new(),
            unresolved_names_complete: true,
            withheld_references: Vec::new(),
            reasons: Vec::new(),
            reference_count: 0,
            batch_count: 0,
            generation: analyzer.project().analysis_generation(),
        })
    }

    pub fn stage_batch(
        &mut self,
        analyzer: &dyn IAnalyzer,
        source_batch: &crate::analyzer::resolution::FactReferenceBatchAnswer,
        edge_batch: &crate::analyzer::resolution::FactReferenceEdgeBatch,
        rows: impl IntoIterator<Item = ReferenceEdgeRow>,
        cancellation: &CancellationToken,
    ) -> bool {
        assert_eq!(edge_batch.generation(), self.generation);
        let status = edge_batch.domain_status(crate::analyzer::resolution::fact_reference_edges::FactReferenceEdgeDeclarationDomain::TypeOrCallable);
        if let EdgeCompleteness::Incomplete { reasons } = status.completeness() {
            for reason in reasons {
                if !self.reasons.contains(reason) {
                    self.reasons.push(reason.clone());
                }
            }
        }
        self.withheld_references
            .extend_from_slice(edge_batch.withheld_references());
        match edge_batch.unresolved_names() {
            Some(names) => self.unresolved_names.extend(names.iter().cloned()),
            None => self.unresolved_names_complete = false,
        }
        for row in rows {
            if cancellation.is_cancelled() {
                return false;
            }
            for unit in row
                .site
                .enclosing
                .iter()
                .chain(std::iter::once(&row.target))
            {
                if is_graph_declaration(unit) && self.rooted_declarations.insert(unit.clone()) {
                    self.declarations
                        .push((unit.clone(), analyzer.ranges(unit)));
                }
            }
            self.rows.push(row);
        }
        self.reference_count += source_batch.answers().len();
        self.batch_count += 1;
        true
    }

    pub fn finish(
        self,
        operation: &mut crate::analyzer::store::resolution_operation::SelectedResolutionOperation<
            '_,
            '_,
        >,
        mut summary: crate::analyzer::resolution::FactResolutionBatchSummary,
        skipped: GraphSkippedCallers,
        mut admitted_callers: HashSet<ProjectFile>,
        ecosystem: UsageEcosystem,
        cancellation: &CancellationToken,
    ) -> StoreResult<SelectedWorkspaceUsageGraphProjectionOutcome> {
        let Self {
            mut declarations,
            rows,
            mut reasons,
            unresolved_names,
            unresolved_names_complete,
            withheld_references,
            reference_count,
            batch_count,
            generation,
            ..
        } = self;
        admitted_callers.retain(|file| !skipped.contains_key(file));
        // Caller exclusion does not exclude endpoints: admitted rows can retain
        // unproven alternatives from platform files outside the fallback build.
        let referenced_targets = rows.iter().map(|row| &row.target).collect::<HashSet<_>>();
        declarations.retain(|(unit, _)| {
            !skipped.contains_key(unit.source()) || referenced_targets.contains(unit)
        });
        assert_eq!(reference_count, summary.reference_count());
        assert_eq!(batch_count, summary.batch_count());
        let completion = summary
            .completion()
            .combine(summary.reference_enumeration_completion());
        summary = match operation.finish_native(summary, &completion, cancellation)? {
            SelectedResolutionOperationOutcome::Native(summary) => summary,
            SelectedResolutionOperationOutcome::Cancelled(_) => {
                return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
            }
            SelectedResolutionOperationOutcome::Stale(_) => {
                return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Stale);
            }
            SelectedResolutionOperationOutcome::Unavailable(reason) => {
                return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Unavailable(
                    format!("{reason:?}"),
                ));
            }
        };
        if cancellation.is_cancelled() {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        }
        if summary.reference_enumeration_completion() != &ResolutionCompletion::Complete
            && !reasons.contains(&EdgeIncompleteReason::ReferenceEnumerationIncomplete)
        {
            reasons.push(EdgeIncompleteReason::ReferenceEnumerationIncomplete);
        }
        let completeness = if reasons.is_empty() {
            EdgeCompleteness::Complete
        } else {
            EdgeCompleteness::Incomplete { reasons }
        };
        let Some(mut accumulator) = NativeWorkspaceUsageGraphAccumulator::new(
            declarations,
            generation,
            ecosystem,
            &admitted_callers,
            cancellation,
        ) else {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        };
        accumulator.record_skipped_callers(skipped);
        if !accumulator.stage(&rows, cancellation) {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        }
        if !accumulator.note_withheld_references(&withheld_references, cancellation) {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        }
        if !accumulator.note_unresolved_names(
            unresolved_names_complete.then_some(&unresolved_names),
            cancellation,
        ) {
            return Ok(SelectedWorkspaceUsageGraphProjectionOutcome::Cancelled);
        }
        let projection = accumulator.finish(&completeness, &summary, rows.len(), cancellation);
        Ok(projection)
    }
}

/// Opaque exact-identity ranking graph built from one selected Java snapshot.
///
/// The graph remains analyzer-owned. Tool-side differential fixtures use it
/// with the production relevance operation supplied by the tools crate.
#[cfg(any(test, feature = "test-support"))]
pub struct SelectedWorkspaceUsageRankingGraph {
    #[doc(hidden)]
    pub graph: WorkspaceUsageRankingGraph,
    #[doc(hidden)]
    pub generation: u64,
    #[doc(hidden)]
    pub reference_count: usize,
    #[doc(hidden)]
    pub projected_edge_count: usize,
    #[doc(hidden)]
    pub batch_count: usize,
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
    /// The tool-side relevance adapter reuses the production cache and
    /// calibrated PageRank implementation through this boundary.
    #[doc(hidden)]
    pub fn into_ranking_graph(self) -> WorkspaceUsageRankingGraph {
        self.graph
    }

    #[doc(hidden)]
    pub fn from_ranking_graph_for_test(graph: WorkspaceUsageRankingGraph, generation: u64) -> Self {
        let projected_edge_count = graph.edges.len();
        Self {
            graph,
            generation,
            reference_count: projected_edge_count,
            projected_edge_count,
            batch_count: 1,
        }
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
#[doc(hidden)]
pub fn validate_selected_workspace_coverage<S>(
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
#[doc(hidden)]
pub fn build_selected_workspace_usage_graph_projection<S>(
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
        same_owner_edges,
        raw_proven_inbound,
        admitted_callers,
        unresolved_names,
        withheld_references,
        forward_completeness,
        kind_projection_complete,
        #[cfg(any(test, feature = "test-support"))]
        resolved_ecosystems,
    } = projection;
    let projection = SelectedWorkspaceUsageGraphProjection {
        nodes,
        edges,
        same_owner_edges,
        raw_proven_inbound,
        admitted_callers,
        skipped_callers: Default::default(),
        build_selection_unavailable: None,
        domain_discovery_failures: Vec::new(),
        unresolved_names,
        withheld_references,
        forward_completeness,
        kind_projection_complete,
        generation,
        reference_count,
        projected_edge_count,
        batch_count,
        root_binding_metrics,
        #[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn reduce_canonical_reference_edge_rows_to_workspace_usage_graph(
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
