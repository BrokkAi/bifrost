mod common;

use std::sync::Arc;

use brokk_bifrost::analyzer::semantic::{
    CancellationToken, ControlEdgeKind, IcfgEdgeKind, IcfgLimitKind, IcfgProvider,
    IcfgSnapshotLimits, SemanticBudget, SemanticOutcome, SemanticRequest,
};
use brokk_bifrost::{
    AnalyzerConfig, Language, OverlayProject, ProjectFile, TestProject, WorkspaceAnalyzer,
};

use common::{
    InlineTestProject,
    semantic_graph::{
        CallContextSelector, ExpectedIcfgBoundary, ExpectedIcfgBoundaryKind, IcfgGraph,
        IcfgOutcomeKind, IcfgTopologyRenderLimits, PointSelector, icfg_edge,
        resolve_procedure_handle,
    },
};

fn root() -> CallContextSelector {
    CallContextSelector::root()
}

#[test]
fn typescript_direct_call_has_matched_entry_and_normal_return() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/direct.ts",
            r#"
                function leaf(): number {
                    return 1;
                }

                function caller(): number {
                    return leaf() + 1;
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "src/direct.ts",
        PointSelector::new("function caller")
            .procedure("caller")
            .effect("entry"),
    );

    graph
        .bind_call(
            "leaf_call",
            "src/direct.ts",
            PointSelector::new("leaf()")
                .procedure("caller")
                .effect("invoke"),
        )
        .bind_node(
            "caller_entry",
            "src/direct.ts",
            PointSelector::new("function caller")
                .procedure("caller")
                .effect("entry"),
            root(),
        )
        .bind_node(
            "leaf_invoke",
            "src/direct.ts",
            PointSelector::new("leaf()")
                .procedure("caller")
                .effect("invoke"),
            root(),
        )
        .bind_node(
            "leaf_entry",
            "src/direct.ts",
            PointSelector::new("function leaf")
                .procedure("leaf")
                .effect("entry"),
            ["leaf_call"],
        )
        .bind_node(
            "leaf_exit",
            "src/direct.ts",
            PointSelector::new("function leaf")
                .procedure("leaf")
                .effect("normal_exit"),
            ["leaf_call"],
        )
        .bind_node(
            "caller_continuation",
            "src/direct.ts",
            PointSelector::new("leaf()")
                .procedure("caller")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
            root(),
        );

    graph.assert_outcome(IcfgOutcomeKind::Complete);
    graph.assert_successors(
        "leaf_invoke",
        &[icfg_edge("leaf_entry", IcfgEdgeKind::Call).originating_call("leaf_call")],
    );
    graph.assert_predecessors(
        "leaf_entry",
        &[icfg_edge("leaf_invoke", IcfgEdgeKind::Call).originating_call("leaf_call")],
    );
    graph.assert_successors(
        "leaf_exit",
        &[icfg_edge("caller_continuation", IcfgEdgeKind::NormalReturn)
            .originating_call("leaf_call")],
    );
    graph.assert_reachable("caller_entry", "caller_continuation");
    graph.assert_adjacency_symmetric();

    let first = graph.render_topology();
    let second = graph.render_topology();
    assert_eq!(first, second);
    assert!(!first.contains("IcfgNodeId"));
    assert!(!first.contains("IcfgEdgeId"));
}

#[test]
fn typescript_cross_file_call_materializes_target_on_demand() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/target.ts",
            r#"
                export function target(): number {
                    return 21;
                }
            "#,
        )
        .file(
            "src/consumer.ts",
            r#"
                import { target } from "./target";

                export function caller(): number {
                    const value = target();
                    const doubled = value * 2;
                    return doubled;
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "src/consumer.ts",
        PointSelector::new("function caller")
            .procedure("caller")
            .effect("entry"),
    );

    graph
        .bind_call(
            "target_call",
            "src/consumer.ts",
            PointSelector::new("target()")
                .procedure("caller")
                .effect("invoke"),
        )
        .bind_node(
            "invoke",
            "src/consumer.ts",
            PointSelector::new("target()")
                .procedure("caller")
                .effect("invoke"),
            root(),
        )
        .bind_node(
            "target_entry",
            "src/target.ts",
            PointSelector::new("function target")
                .procedure("target")
                .effect("entry"),
            ["target_call"],
        )
        .bind_node(
            "target_exit",
            "src/target.ts",
            PointSelector::new("function target")
                .procedure("target")
                .effect("normal_exit"),
            ["target_call"],
        )
        .bind_node(
            "continuation",
            "src/consumer.ts",
            PointSelector::new("target()")
                .procedure("caller")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
            root(),
        )
        .bind_node(
            "doubled",
            "src/consumer.ts",
            PointSelector::new("value * 2")
                .procedure("caller")
                .effect("gap"),
            root(),
        );

    graph.assert_outcome(IcfgOutcomeKind::Complete);
    graph.assert_successors(
        "invoke",
        &[icfg_edge("target_entry", IcfgEdgeKind::Call).originating_call("target_call")],
    );
    graph.assert_successors(
        "target_exit",
        &[icfg_edge("continuation", IcfgEdgeKind::NormalReturn).originating_call("target_call")],
    );
    graph.assert_reachable("continuation", "doubled");
    graph.assert_adjacency_symmetric();
}

#[test]
fn two_call_sites_to_one_callee_never_cross_return_contexts() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/two_sites.ts",
            r#"
                function callee(tag: number): number {
                    return tag;
                }

                function caller(): number {
                    const first = callee(1);
                    const second = callee(2);
                    return first + second;
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "src/two_sites.ts",
        PointSelector::new("function caller")
            .procedure("caller")
            .effect("entry"),
    );

    graph
        .bind_call(
            "first_call",
            "src/two_sites.ts",
            PointSelector::new("callee(1)")
                .procedure("caller")
                .effect("invoke"),
        )
        .bind_call(
            "second_call",
            "src/two_sites.ts",
            PointSelector::new("callee(2)")
                .procedure("caller")
                .effect("invoke"),
        )
        .bind_node(
            "first_invoke",
            "src/two_sites.ts",
            PointSelector::new("callee(1)")
                .procedure("caller")
                .effect("invoke"),
            root(),
        )
        .bind_node(
            "second_invoke",
            "src/two_sites.ts",
            PointSelector::new("callee(2)")
                .procedure("caller")
                .effect("invoke"),
            root(),
        )
        .bind_node(
            "first_exit",
            "src/two_sites.ts",
            PointSelector::new("function callee")
                .procedure("callee")
                .effect("normal_exit"),
            ["first_call"],
        )
        .bind_node(
            "second_exit",
            "src/two_sites.ts",
            PointSelector::new("function callee")
                .procedure("callee")
                .effect("normal_exit"),
            ["second_call"],
        )
        .bind_node(
            "first_continuation",
            "src/two_sites.ts",
            PointSelector::new("callee(1)")
                .procedure("caller")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
            root(),
        )
        .bind_node(
            "second_continuation",
            "src/two_sites.ts",
            PointSelector::new("callee(2)")
                .procedure("caller")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
            root(),
        );

    graph.assert_successors(
        "first_exit",
        &[icfg_edge("first_continuation", IcfgEdgeKind::NormalReturn)
            .originating_call("first_call")],
    );
    graph.assert_successors(
        "second_exit",
        &[icfg_edge("second_continuation", IcfgEdgeKind::NormalReturn)
            .originating_call("second_call")],
    );
    graph.assert_predecessors(
        "first_continuation",
        &[icfg_edge("first_exit", IcfgEdgeKind::NormalReturn).originating_call("first_call")],
    );
    graph.assert_predecessors(
        "second_continuation",
        &[icfg_edge("second_exit", IcfgEdgeKind::NormalReturn).originating_call("second_call")],
    );
    graph.assert_adjacency_symmetric();
}

#[test]
fn java_static_method_dispatch_selects_the_arity_overload() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/Sample.java",
            r#"
                class Sample {
                    static int target() { return 0; }
                    static int target(String value) { return 1; }

                    static int caller() {
                        return target("x");
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "src/Sample.java",
        PointSelector::new("static int caller")
            .procedure("caller")
            .effect("entry"),
    );

    graph
        .bind_call(
            "target_call",
            "src/Sample.java",
            PointSelector::new("target(\"x\")")
                .procedure("caller")
                .effect("invoke"),
        )
        .bind_node(
            "invoke",
            "src/Sample.java",
            PointSelector::new("target(\"x\")")
                .procedure("caller")
                .effect("invoke"),
            root(),
        )
        .bind_node(
            "string_target_entry",
            "src/Sample.java",
            PointSelector::new("static int target(String value)")
                .procedure("target")
                .effect("entry"),
            ["target_call"],
        )
        .bind_node(
            "string_target_exit",
            "src/Sample.java",
            PointSelector::new("static int target(String value)")
                .procedure("target")
                .effect("normal_exit"),
            ["target_call"],
        )
        .bind_node(
            "continuation",
            "src/Sample.java",
            PointSelector::new("target(\"x\")")
                .procedure("caller")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
            root(),
        );

    graph.assert_outcome(IcfgOutcomeKind::Complete);
    graph.assert_successors(
        "invoke",
        &[icfg_edge("string_target_entry", IcfgEdgeKind::Call).originating_call("target_call")],
    );
    graph.assert_successors(
        "string_target_exit",
        &[icfg_edge("continuation", IcfgEdgeKind::NormalReturn).originating_call("target_call")],
    );
    graph.assert_adjacency_symmetric();
}

#[test]
fn java_same_arity_overloads_preserve_every_dispatch_candidate() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/Ambiguous.java",
            r#"
                class Ambiguous {
                    static int target(String value) { return 1; }
                    static int target(Object value) { return 2; }

                    static int caller() {
                        return target("x");
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "src/Ambiguous.java",
        PointSelector::new("static int caller")
            .procedure("caller")
            .effect("entry"),
    );

    graph
        .bind_call(
            "target_call",
            "src/Ambiguous.java",
            PointSelector::new("target(\"x\")")
                .procedure("caller")
                .effect("invoke"),
        )
        .bind_node(
            "invoke",
            "src/Ambiguous.java",
            PointSelector::new("target(\"x\")")
                .procedure("caller")
                .effect("invoke"),
            root(),
        )
        .bind_node(
            "string_target",
            "src/Ambiguous.java",
            PointSelector::new("static int target(String value)")
                .procedure("target")
                .effect("entry"),
            ["target_call"],
        )
        .bind_node(
            "object_target",
            "src/Ambiguous.java",
            PointSelector::new("static int target(Object value)")
                .procedure("target")
                .effect("entry"),
            ["target_call"],
        );

    // This resolver path reports `Resolved` with multiple proven candidate
    // bodies. Candidate multiplicity, rather than the outer outcome, carries
    // the multi-target dispatch fact.
    graph.assert_outcome(IcfgOutcomeKind::Complete);
    graph.assert_successors(
        "invoke",
        &[
            icfg_edge("string_target", IcfgEdgeKind::Call).originating_call("target_call"),
            icfg_edge("object_target", IcfgEdgeKind::Call).originating_call("target_call"),
        ],
    );
    graph.assert_adjacency_symmetric();
}

#[test]
fn java_instance_method_dispatch_enters_the_selected_method() {
    let project = InlineTestProject::with_language(Language::Java)
        .file(
            "src/Methods.java",
            r#"
                class Service {
                    int run() { return 1; }
                }

                class Consumer {
                    int caller(Service service) {
                        return service.run();
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "src/Methods.java",
        PointSelector::new("int caller(Service service)")
            .procedure("caller")
            .effect("entry"),
    );

    graph
        .bind_call(
            "run_call",
            "src/Methods.java",
            PointSelector::new("service.run()")
                .procedure("caller")
                .effect("invoke"),
        )
        .bind_node(
            "invoke",
            "src/Methods.java",
            PointSelector::new("service.run()")
                .procedure("caller")
                .effect("invoke"),
            root(),
        )
        .bind_node(
            "run_entry",
            "src/Methods.java",
            PointSelector::new("int run()")
                .procedure("run")
                .effect("entry"),
            ["run_call"],
        );

    graph.assert_outcome(IcfgOutcomeKind::Complete);
    graph.assert_successors(
        "invoke",
        &[icfg_edge("run_entry", IcfgEdgeKind::Call).originating_call("run_call")],
    );
    graph.assert_adjacency_symmetric();
}

#[test]
fn explicit_throw_returns_to_the_exact_caller_handler() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/exceptional.ts",
            r#"
                function fail(error: Error): never {
                    throw error;
                }

                function caller(error: Error): number {
                    try {
                        fail(error);
                        return 0;
                    } catch {
                        return 1;
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "src/exceptional.ts",
        PointSelector::new("function caller")
            .procedure("caller")
            .effect("entry"),
    );

    graph
        .bind_call(
            "fail_call",
            "src/exceptional.ts",
            PointSelector::new("fail(error)")
                .procedure("caller")
                .effect("invoke"),
        )
        .bind_node(
            "invoke",
            "src/exceptional.ts",
            PointSelector::new("fail(error)")
                .procedure("caller")
                .effect("invoke"),
            root(),
        )
        .bind_node(
            "fail_entry",
            "src/exceptional.ts",
            PointSelector::new("function fail")
                .procedure("fail")
                .effect("entry"),
            ["fail_call"],
        )
        .bind_node(
            "fail_exceptional_exit",
            "src/exceptional.ts",
            PointSelector::new("function fail")
                .procedure("fail")
                .effect("exceptional_exit"),
            ["fail_call"],
        )
        .bind_node(
            "handler_continuation",
            "src/exceptional.ts",
            PointSelector::new("fail(error)")
                .procedure("caller")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
            root(),
        )
        .bind_node(
            "catch_return",
            "src/exceptional.ts",
            PointSelector::new("return 1;")
                .procedure("caller")
                .effect("procedure_return"),
            root(),
        );

    graph.assert_successors(
        "invoke",
        &[icfg_edge("fail_entry", IcfgEdgeKind::Call).originating_call("fail_call")],
    );
    graph.assert_successors(
        "fail_exceptional_exit",
        &[
            icfg_edge("handler_continuation", IcfgEdgeKind::ExceptionalReturn)
                .originating_call("fail_call"),
        ],
    );
    graph.assert_reachable("handler_continuation", "catch_return");
    graph.assert_adjacency_symmetric();
}

#[test]
fn recursive_contexts_are_distinct_and_call_depth_is_typed() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/recursive.ts",
            r#"
                function recurse(n: number): number {
                    if (n <= 0) return 0;
                    return recurse(n - 1);
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let limits = IcfgSnapshotLimits::new(2, 10_000, 20_000).unwrap();
    let mut graph = IcfgGraph::materialize_with_limits(
        &project,
        &analyzer,
        "src/recursive.ts",
        PointSelector::new("function recurse")
            .procedure("recurse")
            .effect("entry"),
        limits,
    );

    graph
        .bind_call(
            "recursive_call",
            "src/recursive.ts",
            PointSelector::new("recurse(n - 1)")
                .procedure("recurse")
                .effect("invoke"),
        )
        .bind_node(
            "root_entry",
            "src/recursive.ts",
            PointSelector::new("function recurse")
                .procedure("recurse")
                .effect("entry"),
            root(),
        )
        .bind_node(
            "first_entry",
            "src/recursive.ts",
            PointSelector::new("function recurse")
                .procedure("recurse")
                .effect("entry"),
            ["recursive_call"],
        )
        .bind_node(
            "second_entry",
            "src/recursive.ts",
            PointSelector::new("function recurse")
                .procedure("recurse")
                .effect("entry"),
            ["recursive_call", "recursive_call"],
        )
        .bind_node(
            "depth_frontier",
            "src/recursive.ts",
            PointSelector::new("recurse(n - 1)")
                .procedure("recurse")
                .effect("invoke"),
            ["recursive_call", "recursive_call"],
        );

    graph.assert_outcome(IcfgOutcomeKind::Unknown);
    graph.assert_boundary(
        "depth_frontier",
        ExpectedIcfgBoundary::new(ExpectedIcfgBoundaryKind::Limit(IcfgLimitKind::CallDepth))
            .originating_call("recursive_call"),
    );
    graph.assert_reachable("root_entry", "first_entry");
    graph.assert_reachable("first_entry", "second_entry");
    graph.assert_adjacency_symmetric();
}

#[test]
fn unresolved_and_external_calls_remain_typed_boundaries() {
    let unresolved_project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/unresolved.ts",
            r#"
                function caller(): number {
                    missing();
                    return 1;
                }
            "#,
        )
        .build();
    let unresolved_analyzer = unresolved_project.workspace_analyzer(AnalyzerConfig::default());
    let mut unresolved = IcfgGraph::materialize(
        &unresolved_project,
        &unresolved_analyzer,
        "src/unresolved.ts",
        PointSelector::new("function caller")
            .procedure("caller")
            .effect("entry"),
    );
    unresolved
        .bind_call(
            "missing_call",
            "src/unresolved.ts",
            PointSelector::new("missing()")
                .procedure("caller")
                .effect("invoke"),
        )
        .bind_node(
            "missing_invoke",
            "src/unresolved.ts",
            PointSelector::new("missing()")
                .procedure("caller")
                .effect("invoke"),
            root(),
        );
    unresolved.assert_outcome(IcfgOutcomeKind::Unknown);
    unresolved.assert_boundary(
        "missing_invoke",
        ExpectedIcfgBoundary::new(ExpectedIcfgBoundaryKind::DispatchUnresolved)
            .originating_call("missing_call"),
    );
    unresolved.assert_successors("missing_invoke", &[]);

    let external_project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/external.ts",
            r#"
                import { work } from "third-party";

                function caller(): number {
                    work();
                    return 1;
                }
            "#,
        )
        .build();
    let external_analyzer = external_project.workspace_analyzer(AnalyzerConfig::default());
    let mut external = IcfgGraph::materialize(
        &external_project,
        &external_analyzer,
        "src/external.ts",
        PointSelector::new("function caller")
            .procedure("caller")
            .effect("entry"),
    );
    external
        .bind_call(
            "external_call",
            "src/external.ts",
            PointSelector::new("work()")
                .procedure("caller")
                .effect("invoke"),
        )
        .bind_node(
            "external_invoke",
            "src/external.ts",
            PointSelector::new("work()")
                .procedure("caller")
                .effect("invoke"),
            root(),
        );
    external.assert_boundary(
        "external_invoke",
        ExpectedIcfgBoundary::new(ExpectedIcfgBoundaryKind::DispatchExternal)
            .originating_call("external_call"),
    );
    external.assert_successors("external_invoke", &[]);
}

#[test]
fn limits_cancellation_and_bounded_rendering_are_explicit() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/limits.ts",
            r#"
                function caller(): number {
                    const value = 1;
                    return value;
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = IcfgGraph::materialize_with_limits(
        &project,
        &analyzer,
        "src/limits.ts",
        PointSelector::new("function caller")
            .procedure("caller")
            .effect("entry"),
        IcfgSnapshotLimits::new(1, 1, 100).unwrap(),
    );
    graph.bind_node(
        "entry",
        "src/limits.ts",
        PointSelector::new("function caller")
            .procedure("caller")
            .effect("entry"),
        root(),
    );
    graph.assert_outcome(IcfgOutcomeKind::Unknown);
    graph.assert_boundary(
        "entry",
        ExpectedIcfgBoundary::new(ExpectedIcfgBoundaryKind::Limit(IcfgLimitKind::Nodes)),
    );
    graph.assert_adjacency_symmetric();

    let bounded = graph.render_topology_with_limits(IcfgTopologyRenderLimits {
        max_nodes: 1,
        max_edges: 1,
        max_boundaries: 1,
        max_output_bytes: 512,
    });
    assert!(bounded.len() <= 512);
    assert!(!bounded.contains("IcfgNodeId"));

    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/limits.ts",
        PointSelector::new("function caller")
            .procedure("caller")
            .effect("entry"),
    );
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let mut cancellation_budget = SemanticBudget::default();
    let cancelled = analyzer
        .icfg_provider()
        .snapshot(
            &root,
            IcfgSnapshotLimits::default(),
            &mut SemanticRequest::new(&mut cancellation_budget, &cancellation),
        )
        .unwrap();
    assert!(matches!(cancelled, SemanticOutcome::Cancelled { .. }));

    let active = CancellationToken::default();
    let mut tiny_budget = SemanticBudget::uniform(1).unwrap();
    let exhausted = analyzer
        .icfg_provider()
        .snapshot(
            &root,
            IcfgSnapshotLimits::default(),
            &mut SemanticRequest::new(&mut tiny_budget, &active),
        )
        .unwrap();
    assert!(matches!(
        exhausted,
        SemanticOutcome::ExceededBudget {
            partial: Some(_),
            ..
        }
    ));
}

#[test]
fn edge_limit_never_publishes_or_expands_an_orphan_target() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/edge_limit.ts",
            r#"
                function caller(): number {
                    const value = 1;
                    return value;
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let root = resolve_procedure_handle(
        &project,
        &analyzer,
        "src/edge_limit.ts",
        PointSelector::new("function caller")
            .procedure("caller")
            .effect("entry"),
    );
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let outcome = analyzer
        .icfg_provider()
        .snapshot(
            &root,
            IcfgSnapshotLimits::new(8, 100, 1).unwrap(),
            &mut SemanticRequest::new(&mut budget, &cancellation),
        )
        .unwrap();
    let snapshot = outcome.available_value().expect("bounded partial snapshot");
    assert_eq!(snapshot.edge_count(), 1);
    assert_eq!(snapshot.node_count(), 2);
    for node in snapshot.node_ids().skip(1) {
        assert!(
            snapshot.predecessor_edges(node).len() > 0,
            "edge limit published an orphan target node"
        );
    }
}

#[test]
fn stale_call_free_root_is_rejected_before_snapshot_traversal() {
    let temp = tempfile::tempdir().unwrap();
    let root_path = temp.path().canonicalize().unwrap();
    let file = ProjectFile::new(root_path.clone(), "src/stale.ts");
    file.write("function caller(): number { return 1; }\n")
        .unwrap();
    let delegate = Arc::new(TestProject::new(root_path, Language::TypeScript));
    let overlay = Arc::new(OverlayProject::new(delegate));
    let analyzer = WorkspaceAnalyzer::build(overlay.clone(), AnalyzerConfig::default());
    let cancellation = CancellationToken::default();
    let mut budget = SemanticBudget::default();
    let artifact = analyzer
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .unwrap()
        .available_value()
        .cloned()
        .expect("initial semantic artifact");
    let caller = artifact
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some("caller")
        })
        .and_then(|procedure| artifact.procedure_handle(procedure.id()))
        .expect("caller procedure handle");

    assert!(overlay.set(
        file.abs_path(),
        "function caller(): number { return 2; }\n".to_owned()
    ));
    let mut snapshot_budget = SemanticBudget::default();
    let error = analyzer
        .icfg_provider()
        .snapshot(
            &caller,
            IcfgSnapshotLimits::default(),
            &mut SemanticRequest::new(&mut snapshot_budget, &cancellation),
        )
        .expect_err("stale root must be rejected");
    assert!(error.to_string().contains("no longer matches"));
}

#[test]
fn nested_calls_dispatch_by_the_exact_whole_call_span() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "src/nested.ts",
            r#"
                function inner(): number { return 1; }
                function outer(value: number): number { return value; }

                function caller(): number {
                    return outer(inner());
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "src/nested.ts",
        PointSelector::new("function caller")
            .procedure("caller")
            .effect("entry"),
    );

    graph
        .bind_call(
            "inner_call",
            "src/nested.ts",
            PointSelector::new("inner()")
                .procedure("caller")
                .effect("invoke"),
        )
        .bind_call(
            "outer_call",
            "src/nested.ts",
            PointSelector::new("outer(inner())")
                .procedure("caller")
                .effect("invoke"),
        )
        .bind_node(
            "inner_invoke",
            "src/nested.ts",
            PointSelector::new("inner()")
                .procedure("caller")
                .effect("invoke"),
            root(),
        )
        .bind_node(
            "inner_entry",
            "src/nested.ts",
            PointSelector::new("function inner")
                .procedure("inner")
                .effect("entry"),
            ["inner_call"],
        )
        .bind_node(
            "outer_invoke",
            "src/nested.ts",
            PointSelector::new("outer(inner())")
                .procedure("caller")
                .effect("invoke"),
            root(),
        )
        .bind_node(
            "outer_entry",
            "src/nested.ts",
            PointSelector::new("function outer")
                .procedure("outer")
                .effect("entry"),
            ["outer_call"],
        );

    graph.assert_successors(
        "inner_invoke",
        &[icfg_edge("inner_entry", IcfgEdgeKind::Call).originating_call("inner_call")],
    );
    graph.assert_successors(
        "outer_invoke",
        &[icfg_edge("outer_entry", IcfgEdgeKind::Call).originating_call("outer_call")],
    );
    graph.assert_reachable("inner_entry", "outer_invoke");
    graph.assert_adjacency_symmetric();
}
