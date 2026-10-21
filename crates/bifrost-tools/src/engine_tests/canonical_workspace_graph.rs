#[cfg(test)]
mod tests {

    use std::collections::BTreeSet;

    use brokk_bifrost_analysis::analyzer::resolution::model::BindingFragmentId;

    use brokk_bifrost_core::cancellation::CancellationToken;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::CanonicalWorkspaceUsageCatalog;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::CanonicalWorkspaceUsageGraphAccumulator;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::CanonicalWorkspaceUsageGraphBuildOutcome;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::CanonicalWorkspaceUsageGraphProjection;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::CanonicalWorkspaceUsageGraphProjectionOutcome;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::CanonicalWorkspaceUsageNodeRemapping;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::CanonicalWorkspaceUsageNodeRemappingOutcome;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::CanonicalWorkspaceUsageProjectedEdge;

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use brokk_bifrost_core::analyzer::model::DeclarationId;

    use brokk_bifrost_core::analyzer::structural::edges::EdgeAxis;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeCompleteness;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeIncompleteReason;

    use brokk_bifrost_core::analyzer::structural::edges::EdgeProvenance;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeCatalog;

    use brokk_bifrost_core::hash::HashMap;

    use brokk_bifrost_core::hash::HashSet;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_analysis::analyzer::usages::inverted_edges::MAX_CALLSITES;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_core::analyzer::model::Range;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::ReferenceEdgeRow;

    use brokk_bifrost_core::analyzer::usages::model::ReferenceKind;

    use brokk_bifrost_analysis::analyzer::resolution::batch::ResolutionBatchMetrics;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::SelectedWorkspaceUsageGraphProjection;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::SelectedWorkspaceUsageGraphProjectionOutcome;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::SelectedWorkspaceUsageRankingBuildOutcome;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::SelectedWorkspaceUsageRankingGraph;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::UsageEcosystem;

    use brokk_bifrost_core::analyzer::usages::model::UsageHitKind;

    use brokk_bifrost_core::analyzer::usages::model::UsageProof;

    use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageReferenceCounts;

    use brokk_bifrost_core::analyzer::usages::inverted_edges::UsageReferenceKind;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageEdge;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageGraph;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageGraphBuildOutcome;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageNode;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageRankingGraph;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::WorkspaceUsageRankingNode;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::aggregate_disjoint_workspace_usage_projections;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::build_selected_workspace_usage_ranking_graph;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::is_graph_declaration;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::merge_workspace_usage_graph_projections;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::projected_edges_into_ranking_edges;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::reduce_canonical_reference_edge_rows_to_workspace_usage_graph;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::remap_workspace_usage_projection_nodes;

    use brokk_bifrost_analysis::analyzer::usages::workspace_graph::canonical_workspace_graph::validate_selected_workspace_coverage;

    use brokk_bifrost_analysis::analyzer::resolution::fact_reference_edges::FactReferenceEdgeSelectedFragment;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::PreloadedFactResolutionService;

    use brokk_bifrost_analysis::analyzer::resolution::fact_resolution::SelectedFactResolutionEngine;

    use brokk_bifrost_analysis::analyzer::structural::reference_edges::EdgeSite;

    use brokk_bifrost_core::analyzer::structural::edges::OwnerRelation;

    use brokk_bifrost_core::analyzer::structural::edges::SiteClass;

    use brokk_bifrost_core::analyzer::model::CodeUnitType;

    use brokk_bifrost_analysis::analyzer::java::JavaAnalyzer;

    use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
    use brokk_bifrost_core::analyzer::CodeUnitIndex;
    use brokk_bifrost_core::analyzer::project::OverlayProject;
    use std::sync::Arc;

    const CANONICAL_GENERATION: u64 = 17;

    fn test_file(path: &str) -> ProjectFile {
        let root = std::env::current_dir().expect("the test working directory must be available");
        brokk_bifrost_analysis::analyzer::common::project_file_for_test(&root, path)
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
            ambiguous_candidate: false,
            usage_kind: UsageHitKind::Reference,
            site_class: SiteClass::UseSite,
            owner_relation: OwnerRelation::External,
            provenance: EdgeProvenance::Forward,
            generation: CANONICAL_GENERATION,
        }
    }

    fn stage_permuted_batches(
        make_accumulator: impl Fn() -> CanonicalWorkspaceUsageGraphAccumulator,
        first_batch: &[ReferenceEdgeRow],
        second_batch: &[ReferenceEdgeRow],
        cancellation: &CancellationToken,
    ) -> (
        CanonicalWorkspaceUsageGraphAccumulator,
        CanonicalWorkspaceUsageGraphAccumulator,
    ) {
        let mut forward = make_accumulator();
        assert!(forward.stage_rows(first_batch, cancellation));
        assert!(forward.stage_rows(second_batch, cancellation));

        let mut reverse = make_accumulator();
        assert!(reverse.stage_rows(second_batch, cancellation));
        assert!(reverse.stage_rows(first_batch, cancellation));
        (forward, reverse)
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
            skipped_callers: Default::default(),
            build_selection_unavailable: None,
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
            skipped_callers: Default::default(),
            build_selection_unavailable: None,
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
        let (forward, reverse) = stage_permuted_batches(
            || {
                CanonicalWorkspaceUsageGraphAccumulator::new(
                    make_catalog(),
                    selected.clone(),
                    admitted.clone(),
                )
            },
            &first_batch,
            &second_batch,
            &cancellation,
        );
        let forward = complete_canonical_graph(forward.finish(
            CANONICAL_GENERATION,
            &EdgeCompleteness::Complete,
            &cancellation,
        ));
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
        let (forward, reverse) = stage_permuted_batches(
            || {
                CanonicalWorkspaceUsageGraphAccumulator::new(
                    make_catalog(),
                    selected.clone(),
                    admitted.clone(),
                )
            },
            &first_batch,
            &second_batch,
            &cancellation,
        );
        let forward = complete_canonical_projection(forward.finish_projection(
            CANONICAL_GENERATION,
            &EdgeCompleteness::Complete,
            &cancellation,
        ));
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
        let target_index = node_index(&graph, &target);
        let python_target = node_index(&graph, &python_target);
        assert_eq!(graph.nodes[target_index].unproven_inbound, 2);
        assert_eq!(graph.nodes[target_index].truncated_inbound, None);
        assert_eq!(graph.nodes[python_target].unproven_inbound, 0);
        assert!(graph.edges.iter().all(|edge| edge.to != target_index));
        assert_eq!(graph.resolved_ecosystems, vec![UsageEcosystem::Jvm]);

        let mut ambiguous_candidate = canonical_row(
            &caller_file,
            test_range(140, 146, 9),
            &caller,
            &target,
            Some(ReferenceKind::MethodCall),
            UsageProof::Unproven,
        );
        ambiguous_candidate.ambiguous_candidate = true;
        let CanonicalWorkspaceUsageGraphBuildOutcome::Complete(candidate_graph) =
            reduce_canonical_reference_edges_to_workspace_usage_graph(
                make_catalog(),
                &[ambiguous_candidate],
                &EdgeCompleteness::Complete,
                &selected,
                &CancellationToken::default(),
            )
        else {
            panic!("closed ambiguous candidates retain exact graph identities");
        };
        let caller = node_index(&candidate_graph, &caller);
        let target = node_index(&candidate_graph, &target);
        assert_eq!(candidate_graph.edges.len(), 1);
        assert_eq!(candidate_graph.edges[0].from, caller);
        assert_eq!(candidate_graph.edges[0].to, target);
        assert_eq!(candidate_graph.edges[0].counts.calls, 1);
        assert_eq!(candidate_graph.nodes[target].unproven_inbound, 1);

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
        let lexical = brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
            fragment,
            Language::Java,
            &facts,
        )
        .lexical()
        .clone();
        let typed = brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
            fragment,
            Language::Java,
            &facts,
        )
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
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
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
            brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                other_fragment,
                Language::Java,
                &facts,
            )
            .lexical()
            .clone();
        let other_typed =
            brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
                other_fragment,
                Language::Java,
                &facts,
            )
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

    #[test]
    fn selected_java_ranking_cancellation_publishes_no_prefix_and_retry_is_exact() {
        let (_project, graph, seed, expected_files) = selected_java_ranking_adapter_fixture();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        assert!(
            crate::relevance::selected_exact_relevance::rank_exact_workspace_usage_graph_with_cancellation(
                &graph.graph,
                &[(seed.clone(), 1.0)],
                10,
                &cancellation
            )
            .is_none(),
            "a cancelled exact rank must publish no candidate prefix"
        );

        let retry = crate::relevance::selected_exact_relevance::rank_exact_workspace_usage_graph_with_cancellation(
            &graph.graph,
            &[(seed, 1.0)],
            10,
            &CancellationToken::default(),
        )
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
            crate::relevance::selected_exact_relevance::rank_exact_workspace_usage_graph_with_cancellation(
                &graph.graph,
                &[(seed.clone(), 1.0)],
                0,
                &cancellation
            )
            .is_none(),
            "cancellation must outrank the incumbent zero-limit fast path"
        );

        graph.graph.edges.clear();
        assert!(
            crate::relevance::selected_exact_relevance::rank_exact_workspace_usage_graph_with_cancellation(
                &graph.graph,
                &[(seed, 1.0)],
                10,
                &cancellation
            )
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

        let first = crate::relevance::selected_exact_relevance::rank_exact_workspace_usage_graph_with_cancellation(
            &graph.graph,
            &[(seed.clone(), 1.0)],
            10,
            &CancellationToken::default(),
        )
        .expect("the first exact ranking must finish");
        let warm = crate::relevance::selected_exact_relevance::rank_exact_workspace_usage_graph_with_cancellation(
            &graph.graph,
            &[(seed, 1.0)],
            10,
            &CancellationToken::default(),
        )
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
        let lexical = brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
            fragment,
            Language::Java,
            &facts,
        )
        .lexical()
        .clone();
        let typed = brokk_bifrost_analysis::analyzer::resolution::fact_lowering::lower_for_test(
            fragment,
            Language::Java,
            &facts,
        )
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
                brokk_bifrost_analysis::analyzer::resolution::local_identity::test_shared_names(),
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
}
