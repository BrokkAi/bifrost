mod common;

use brokk_bifrost::analyzer::semantic::{
    CallableTargetResolution, ControlEdgeKind, DeclarationSegmentKind, DeferredInvocationKind,
    IcfgEdgeKind, ProcedureInvocationKind, ProcedureKind, SemanticCapability, SemanticEffect,
    SemanticGapKind, SemanticGapSubject, SemanticLanguage,
};
use brokk_bifrost::{AnalyzerConfig, Language};

use common::{
    InlineTestProject,
    semantic_graph::{
        CallContextSelector, ExpectedIcfgBoundary, ExpectedIcfgBoundaryKind, IcfgGraph,
        IcfgOutcomeKind, PointSelector, SemanticGraph, edge as cfg_edge, icfg_edge,
    },
};

#[derive(Debug, Clone, Copy)]
struct DirectCallFixture {
    language: Language,
    dialect: SemanticLanguage,
    callee_path: &'static str,
    callee_source: &'static str,
    callee_declaration: &'static str,
    callee_name: &'static str,
    caller_path: &'static str,
    caller_source: &'static str,
    caller_declaration: &'static str,
    caller_name: &'static str,
    call: &'static str,
}

fn root() -> CallContextSelector {
    CallContextSelector::root()
}

fn assert_direct_call_conformance(fixture: DirectCallFixture) {
    let project = InlineTestProject::with_language(fixture.language)
        .file(fixture.callee_path, fixture.callee_source)
        .file(fixture.caller_path, fixture.caller_source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut cfg = SemanticGraph::materialize(&project, &analyzer, fixture.caller_path);

    assert_eq!(cfg.artifact().key().language(), fixture.dialect);
    cfg.bind(
        "caller_entry",
        PointSelector::new(fixture.caller_declaration)
            .procedure(fixture.caller_name)
            .effect("entry"),
    )
    .bind(
        "invoke",
        PointSelector::new(fixture.call)
            .procedure(fixture.caller_name)
            .effect("invoke"),
    )
    .bind(
        "normal_continuation",
        PointSelector::new(fixture.call)
            .procedure(fixture.caller_name)
            .effect("call_continuation")
            .outgoing_kind(ControlEdgeKind::Normal),
    )
    .bind(
        "exceptional_continuation",
        PointSelector::new(fixture.call)
            .procedure(fixture.caller_name)
            .effect("call_continuation")
            .outgoing_kind(ControlEdgeKind::Exceptional),
    )
    .bind(
        "caller_exceptional_exit",
        PointSelector::new(fixture.caller_declaration)
            .procedure(fixture.caller_name)
            .effect("exceptional_exit"),
    );

    cfg.assert_successors(
        "invoke",
        &[
            cfg_edge("normal_continuation", ControlEdgeKind::Normal),
            cfg_edge("exceptional_continuation", ControlEdgeKind::Exceptional),
        ],
    );
    cfg.assert_predecessors(
        "normal_continuation",
        &[cfg_edge("invoke", ControlEdgeKind::Normal)],
    );
    cfg.assert_predecessors(
        "exceptional_continuation",
        &[cfg_edge("invoke", ControlEdgeKind::Exceptional)],
    );
    cfg.assert_reachable("caller_entry", "normal_continuation");
    cfg.assert_reachable("exceptional_continuation", "caller_exceptional_exit");
    cfg.assert_adjacency_symmetric();
    let first_cfg_render = cfg.render_topology();
    assert_eq!(first_cfg_render, cfg.render_topology());
    assert!(!first_cfg_render.contains("ProgramPointId"));
    assert!(!first_cfg_render.contains("ControlEdgeId"));

    let mut icfg = IcfgGraph::materialize(
        &project,
        &analyzer,
        fixture.caller_path,
        PointSelector::new(fixture.caller_declaration)
            .procedure(fixture.caller_name)
            .effect("entry"),
    );
    icfg.bind_call(
        "direct_call",
        fixture.caller_path,
        PointSelector::new(fixture.call)
            .procedure(fixture.caller_name)
            .effect("invoke"),
    )
    .bind_node(
        "icfg_caller_entry",
        fixture.caller_path,
        PointSelector::new(fixture.caller_declaration)
            .procedure(fixture.caller_name)
            .effect("entry"),
        root(),
    )
    .bind_node(
        "icfg_invoke",
        fixture.caller_path,
        PointSelector::new(fixture.call)
            .procedure(fixture.caller_name)
            .effect("invoke"),
        root(),
    )
    .bind_node(
        "callee_entry",
        fixture.callee_path,
        PointSelector::new(fixture.callee_declaration)
            .procedure(fixture.callee_name)
            .effect("entry"),
        ["direct_call"],
    )
    .bind_node(
        "callee_normal_exit",
        fixture.callee_path,
        PointSelector::new(fixture.callee_declaration)
            .procedure(fixture.callee_name)
            .effect("normal_exit"),
        ["direct_call"],
    )
    .bind_node(
        "icfg_normal_continuation",
        fixture.caller_path,
        PointSelector::new(fixture.call)
            .procedure(fixture.caller_name)
            .effect("call_continuation")
            .outgoing_kind(ControlEdgeKind::Normal),
        root(),
    );

    icfg.assert_outcome(IcfgOutcomeKind::Complete);
    icfg.assert_successors(
        "icfg_invoke",
        &[icfg_edge("callee_entry", IcfgEdgeKind::Call).originating_call("direct_call")],
    );
    icfg.assert_predecessors(
        "callee_entry",
        &[icfg_edge("icfg_invoke", IcfgEdgeKind::Call).originating_call("direct_call")],
    );
    icfg.assert_successors(
        "callee_normal_exit",
        &[
            icfg_edge("icfg_normal_continuation", IcfgEdgeKind::NormalReturn)
                .originating_call("direct_call"),
        ],
    );
    icfg.assert_predecessors(
        "icfg_normal_continuation",
        &[icfg_edge("callee_normal_exit", IcfgEdgeKind::NormalReturn)
            .originating_call("direct_call")],
    );
    icfg.assert_reachable("icfg_caller_entry", "icfg_normal_continuation");
    icfg.assert_adjacency_symmetric();
    let first_icfg_render = icfg.render_topology();
    assert_eq!(first_icfg_render, icfg.render_topology());
    assert!(!first_icfg_render.contains("IcfgNodeId"));
    assert!(!first_icfg_render.contains("IcfgEdgeId"));
}

#[test]
fn java_direct_call_conformance() {
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::Java,
        dialect: SemanticLanguage::Standard(Language::Java),
        callee_path: "java/conformance/JavaLibrary.java",
        callee_source: r#"
            package conformance;

            final class JavaLibrary {
                static int javaLeaf() {
                    return 7;
                }
            }
        "#,
        callee_declaration: "static int javaLeaf()",
        callee_name: "javaLeaf",
        caller_path: "java/conformance/JavaCaller.java",
        caller_source: r#"
            package conformance;

            final class JavaCaller {
                static int javaRoot() {
                    return JavaLibrary.javaLeaf();
                }
            }
        "#,
        caller_declaration: "static int javaRoot()",
        caller_name: "javaRoot",
        call: "JavaLibrary.javaLeaf()",
    });
}

#[test]
fn go_direct_call_conformance() {
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::Go,
        dialect: SemanticLanguage::Standard(Language::Go),
        callee_path: "go/conformance/library.go",
        callee_source: r#"package conformance

func GoLeaf() int {
    return 7
}
"#,
        callee_declaration: "func GoLeaf() int",
        callee_name: "GoLeaf",
        caller_path: "go/conformance/caller.go",
        caller_source: r#"package conformance

func GoRoot() int {
    return GoLeaf()
}
"#,
        caller_declaration: "func GoRoot() int",
        caller_name: "GoRoot",
        call: "GoLeaf()",
    });
}

#[test]
fn rust_direct_call_conformance() {
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::Rust,
        dialect: SemanticLanguage::Standard(Language::Rust),
        callee_path: "leaf.rs",
        callee_source: r#"
            pub fn rust_leaf() -> i32 {
                7
            }
        "#,
        callee_declaration: "pub fn rust_leaf() -> i32",
        callee_name: "rust_leaf",
        caller_path: "lib.rs",
        caller_source: r#"
            mod leaf;
            use crate::leaf::rust_leaf;

            pub fn rust_root() -> i32 {
                rust_leaf()
            }
        "#,
        caller_declaration: "pub fn rust_root() -> i32",
        caller_name: "rust_root",
        call: "rust_leaf()",
    });
}

#[test]
fn rust_turbofish_direct_call_uses_the_shared_dispatch_oracle() {
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::Rust,
        dialect: SemanticLanguage::Standard(Language::Rust),
        callee_path: "leaf.rs",
        callee_source: r#"
            pub fn generic_leaf<T>() -> i32 {
                7
            }
        "#,
        callee_declaration: "pub fn generic_leaf<T>() -> i32",
        callee_name: "generic_leaf",
        caller_path: "lib.rs",
        caller_source: r#"
            mod leaf;
            use crate::leaf::generic_leaf;

            pub fn generic_root() -> i32 {
                generic_leaf::<u8>()
            }
        "#,
        caller_declaration: "pub fn generic_root() -> i32",
        caller_name: "generic_root",
        call: "generic_leaf::<u8>()",
    });
}

#[test]
fn rust_generic_method_call_uses_the_shared_dispatch_oracle() {
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::Rust,
        dialect: SemanticLanguage::Standard(Language::Rust),
        callee_path: "worker.rs",
        callee_source: r#"
            pub struct Worker;

            impl Worker {
                pub fn step<T>(&self) -> i32 {
                    7
                }
            }
        "#,
        callee_declaration: "pub fn step<T>(&self) -> i32",
        callee_name: "step",
        caller_path: "lib.rs",
        caller_source: r#"
            mod worker;
            use crate::worker::Worker;

            pub fn method_root(worker: &Worker) -> i32 {
                worker.step::<u8>()
            }
        "#,
        caller_declaration: "pub fn method_root(worker: &Worker) -> i32",
        caller_name: "method_root",
        call: "worker.step::<u8>()",
    });
}

#[test]
fn rust_async_function_calls_are_deferred_icfg_boundaries() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "leaf.rs",
            r#"
                pub async fn async_leaf() -> i32 {
                    7
                }
            "#,
        )
        .file(
            "lib.rs",
            r#"
                mod leaf;
                use crate::leaf::async_leaf;

                pub fn make_future() {
                    let _pending = async_leaf();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let callee = SemanticGraph::materialize(&project, &analyzer, "leaf.rs");
    let async_leaf = callee
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some("async_leaf")
        })
        .expect("missing Rust async function procedure");
    assert!(async_leaf.properties().is_async);
    assert!(!async_leaf.properties().is_generator);
    assert_eq!(
        async_leaf.properties().invocation,
        ProcedureInvocationKind::Deferred
    );

    let mut graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "lib.rs",
        PointSelector::new("pub fn make_future()")
            .procedure("make_future")
            .effect("entry"),
    );
    graph
        .bind_call(
            "async_call",
            "lib.rs",
            PointSelector::new("async_leaf()")
                .procedure("make_future")
                .effect("invoke"),
        )
        .bind_node(
            "caller_entry",
            "lib.rs",
            PointSelector::new("pub fn make_future()")
                .procedure("make_future")
                .effect("entry"),
            root(),
        )
        .bind_node(
            "async_invoke",
            "lib.rs",
            PointSelector::new("async_leaf()")
                .procedure("make_future")
                .effect("invoke"),
            root(),
        )
        .bind_node(
            "normal_continuation",
            "lib.rs",
            PointSelector::new("async_leaf()")
                .procedure("make_future")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
            root(),
        )
        .bind_node(
            "exceptional_continuation",
            "lib.rs",
            PointSelector::new("async_leaf()")
                .procedure("make_future")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
            root(),
        );

    graph.assert_outcome(IcfgOutcomeKind::Complete);
    graph.assert_boundary(
        "async_invoke",
        ExpectedIcfgBoundary::new(ExpectedIcfgBoundaryKind::DispatchDeferred(
            DeferredInvocationKind::Async,
        ))
        .originating_call("async_call"),
    );
    graph.assert_successors(
        "async_invoke",
        &[
            icfg_edge(
                "normal_continuation",
                IcfgEdgeKind::CallToNormalContinuation,
            )
            .originating_call("async_call"),
            icfg_edge(
                "exceptional_continuation",
                IcfgEdgeKind::CallToExceptionalContinuation,
            )
            .originating_call("async_call"),
        ],
    );
    graph.assert_predecessors(
        "normal_continuation",
        &[
            icfg_edge("async_invoke", IcfgEdgeKind::CallToNormalContinuation)
                .originating_call("async_call"),
        ],
    );
    graph.assert_reachable("caller_entry", "normal_continuation");
    graph.assert_adjacency_symmetric();
}

#[test]
fn rust_labeled_blocks_do_not_capture_unlabeled_loop_breaks() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "rust/labeled.rs",
            r#"
                fn labeled_flow() {
                    'outer: loop {
                        'block: {
                            if leave_loop() {
                                break;
                            }
                            break 'block;
                        }
                        after_block();
                        break 'outer;
                    }
                    done();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "rust/labeled.rs");
    graph
        .bind(
            "entry",
            PointSelector::new("fn labeled_flow()")
                .procedure("labeled_flow")
                .effect("entry"),
        )
        .bind(
            "leave_invoke",
            PointSelector::new("leave_loop()")
                .procedure("labeled_flow")
                .effect("invoke"),
        )
        .bind(
            "unlabeled_break",
            PointSelector::new("break;")
                .procedure("labeled_flow")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "block_break",
            PointSelector::new("break 'block;")
                .procedure("labeled_flow")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "outer_break",
            PointSelector::new("break 'outer;")
                .procedure("labeled_flow")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "after_block",
            PointSelector::new("after_block()")
                .procedure("labeled_flow")
                .anchor_occurrence(0),
        )
        .bind(
            "done",
            PointSelector::new("done()")
                .procedure("labeled_flow")
                .anchor_occurrence(0),
        );

    graph.assert_reachable("entry", "leave_invoke");
    graph.assert_successors(
        "unlabeled_break",
        &[cfg_edge("done", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "block_break",
        &[cfg_edge("after_block", ControlEdgeKind::Normal)],
    );
    graph.assert_successors("outer_break", &[cfg_edge("done", ControlEdgeKind::Normal)]);
    graph.assert_predecessors(
        "done",
        &[
            cfg_edge("unlabeled_break", ControlEdgeKind::Normal),
            cfg_edge("outer_break", ControlEdgeKind::Normal),
        ],
    );
    graph.assert_adjacency_symmetric();
}

#[test]
fn rust_branches_early_returns_and_dead_syntax_have_exact_topology() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "rust/branch.rs",
            r#"
                fn branch(flag: bool) {
                    before();
                    if flag {
                        yes();
                        return;
                        dead_after_return();
                    } else {
                        no();
                    }
                    after();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "rust/branch.rs");
    graph
        .bind(
            "entry",
            PointSelector::new("fn branch(flag: bool)")
                .procedure("branch")
                .effect("entry"),
        )
        .bind(
            "condition",
            PointSelector::new("flag")
                .occurrence(1)
                .procedure("branch")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "yes_block",
            PointSelector::new(
                r#"{
                        yes();
                        return;
                        dead_after_return();
                    }"#,
            )
            .procedure("branch")
            .anchor_occurrence(0),
        )
        .bind(
            "yes_statement",
            PointSelector::new("yes()")
                .procedure("branch")
                .anchor_occurrence(0),
        )
        .bind(
            "no_block",
            PointSelector::new(
                r#"{
                        no();
                    }"#,
            )
            .procedure("branch")
            .anchor_occurrence(0),
        )
        .bind(
            "no_statement",
            PointSelector::new("no()")
                .procedure("branch")
                .anchor_occurrence(0),
        )
        .bind(
            "no_normal",
            PointSelector::new("no()")
                .procedure("branch")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "return",
            PointSelector::new("return;")
                .procedure("branch")
                .effect("procedure_return"),
        )
        .bind(
            "normal_exit",
            PointSelector::new("fn branch(flag: bool)")
                .procedure("branch")
                .effect("normal_exit"),
        )
        .bind(
            "after_statement",
            PointSelector::new("after()")
                .procedure("branch")
                .anchor_occurrence(0),
        )
        .bind(
            "after_invoke",
            PointSelector::new("after()")
                .procedure("branch")
                .effect("invoke"),
        )
        .bind(
            "dead_invoke",
            PointSelector::new("dead_after_return()")
                .procedure("branch")
                .effect("invoke"),
        );

    graph.assert_successors(
        "condition",
        &[
            cfg_edge("yes_block", ControlEdgeKind::ConditionalTrue),
            cfg_edge("no_block", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "yes_block",
        &[cfg_edge("yes_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "no_block",
        &[cfg_edge("no_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "after_statement",
        &[cfg_edge("no_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "return",
        &[cfg_edge("normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("entry", "after_invoke");
    graph.assert_unreachable("return", "after_invoke");
    graph.assert_unreachable("entry", "dead_invoke");
    graph.assert_adjacency_symmetric();
}

#[test]
fn rust_semicolonless_control_tail_is_an_implicit_value_return() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "rust/control_tail.rs",
            r#"
                fn choose(flag: bool) -> i32 {
                    if flag {
                        left()
                    } else {
                        right()
                    }
                }

                fn choose_unit(flag: bool) {
                    if flag {
                        unit_left();
                    } else {
                        unit_right();
                    };
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "rust/control_tail.rs");
    graph
        .bind(
            "condition",
            PointSelector::new("flag")
                .occurrence(1)
                .procedure("choose")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "left_block",
            PointSelector::new(
                r#"{
                        left()
                    }"#,
            )
            .procedure("choose")
            .anchor_occurrence(0),
        )
        .bind(
            "left",
            PointSelector::new("left()")
                .procedure("choose")
                .anchor_occurrence(0),
        )
        .bind(
            "left_normal",
            PointSelector::new("left()")
                .procedure("choose")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "right_block",
            PointSelector::new(
                r#"{
                        right()
                    }"#,
            )
            .procedure("choose")
            .anchor_occurrence(0),
        )
        .bind(
            "right",
            PointSelector::new("right()")
                .procedure("choose")
                .anchor_occurrence(0),
        )
        .bind(
            "right_normal",
            PointSelector::new("right()")
                .procedure("choose")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "implicit_return",
            PointSelector::new("if flag")
                .occurrence(0)
                .procedure("choose")
                .effect("procedure_return"),
        )
        .bind(
            "normal_exit",
            PointSelector::new("fn choose(flag: bool)")
                .procedure("choose")
                .effect("normal_exit"),
        );

    graph.assert_successors(
        "condition",
        &[
            cfg_edge("left_block", ControlEdgeKind::ConditionalTrue),
            cfg_edge("right_block", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors("left_block", &[cfg_edge("left", ControlEdgeKind::Normal)]);
    graph.assert_successors("right_block", &[cfg_edge("right", ControlEdgeKind::Normal)]);
    graph.assert_successors(
        "left_normal",
        &[cfg_edge("implicit_return", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "right_normal",
        &[cfg_edge("implicit_return", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "implicit_return",
        &[
            cfg_edge("left_normal", ControlEdgeKind::Normal),
            cfg_edge("right_normal", ControlEdgeKind::Normal),
        ],
    );
    graph.assert_successors(
        "implicit_return",
        &[cfg_edge("normal_exit", ControlEdgeKind::Normal)],
    );

    let procedure = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some("choose")
        })
        .expect("missing Rust choose procedure");
    let (return_point, return_value) = procedure
        .points()
        .iter()
        .find_map(|point| {
            point.events.iter().find_map(|event| match event.effect {
                SemanticEffect::ProcedureReturn { value: Some(value) } => Some((point.id, value)),
                _ => None,
            })
        })
        .expect("semicolonless control tail should publish a value return");
    assert!(procedure.gaps().iter().any(|gap| {
        gap.point == return_point
            && gap.subject == SemanticGapSubject::Value(return_value)
            && gap.capability == SemanticCapability::Values
            && gap.kind == SemanticGapKind::Unknown
    }));

    let unit = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some("choose_unit")
        })
        .expect("missing Rust choose_unit procedure");
    assert!(
        unit.points().iter().all(|point| point
            .events
            .iter()
            .all(|event| !matches!(event.effect, SemanticEffect::ProcedureReturn { .. }))),
        "semicolon-terminated unit control flow must not publish a value return"
    );
    graph.assert_adjacency_symmetric();
}

#[test]
fn rust_named_nested_callables_are_separate_with_honest_invocation_kinds() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "rust/callables.rs",
            r#"
                fn top_level() {
                    top_body();
                }

                struct Counter;

                impl Counter {
                    fn step(&self) {
                        method_body();
                    }

                    fn create() {
                        associated_body();
                    }
                }

                fn outer() {
                    fn local() {
                        local_body();
                    }

                    let plain = || {
                        closure_body();
                    };
                    let async_closure = async || {
                        async_closure_body().await;
                    };
                    let future = async move {
                        future_body().await;
                    };
                    let stream = gen move {
                        yield stream_value();
                    };
                    outer_body();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "rust/callables.rs");

    for (alias, declaration, procedure, body_call) in [
        ("top", "fn top_level()", "top_level", "top_body()"),
        ("method", "fn step(&self)", "step", "method_body()"),
        ("associated", "fn create()", "create", "associated_body()"),
        ("local", "fn local()", "local", "local_body()"),
        ("plain", "||", "plain", "closure_body()"),
        (
            "async_closure",
            "async ||",
            "async_closure",
            "async_closure_body()",
        ),
        ("future", "async move", "future", "future_body()"),
        ("stream", "gen move", "stream", "stream_value()"),
        ("outer", "fn outer()", "outer", "outer_body()"),
    ] {
        graph
            .bind(
                format!("{alias}_entry"),
                PointSelector::new(declaration)
                    .procedure(procedure)
                    .effect("entry"),
            )
            .bind(
                format!("{alias}_invoke"),
                PointSelector::new(body_call)
                    .procedure(procedure)
                    .effect("invoke"),
            );
        graph.assert_reachable(&format!("{alias}_entry"), &format!("{alias}_invoke"));
    }

    for body_call in [
        "local_body()",
        "closure_body()",
        "async_closure_body()",
        "future_body()",
        "stream_value()",
    ] {
        let error = graph
            .try_bind(
                format!("outer_must_not_own_{body_call}"),
                PointSelector::new(body_call)
                    .procedure("outer")
                    .effect("invoke"),
            )
            .expect_err("nested callable execution must stay outside the enclosing CFG");
        assert!(
            error.to_string().contains("matched no semantic"),
            "unexpected selector result for {body_call}: {error}"
        );
    }

    let procedures = graph.artifact().procedures();
    let named = |name: &str, kind: ProcedureKind| {
        procedures
            .iter()
            .find(|procedure| {
                procedure.kind() == kind
                    && procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
            })
            .unwrap_or_else(|| panic!("missing Rust {kind:?} procedure {name}"))
    };
    let top = named("top_level", ProcedureKind::Function);
    let method = named("step", ProcedureKind::Method);
    let associated = named("create", ProcedureKind::Method);
    let outer = named("outer", ProcedureKind::Function);
    let local = named("local", ProcedureKind::LocalFunction);
    let plain = named("plain", ProcedureKind::Closure);
    let async_closure = named("async_closure", ProcedureKind::Closure);
    let future = named("future", ProcedureKind::Closure);
    let stream = named("stream", ProcedureKind::Closure);

    for procedure in [top, method, associated, outer] {
        assert!(procedure.lexical_parent().is_none());
    }
    for procedure in [local, plain, async_closure, future, stream] {
        assert_eq!(procedure.lexical_parent(), Some(outer.id()));
    }
    for procedure in [top, method, associated, outer, local, plain] {
        assert!(!procedure.properties().is_async);
        assert!(!procedure.properties().is_generator);
        assert_eq!(
            procedure.properties().invocation,
            ProcedureInvocationKind::Immediate
        );
    }
    assert!(!method.properties().is_static);
    assert!(associated.properties().is_static);
    for procedure in [async_closure, future] {
        assert!(procedure.properties().is_async);
        assert!(!procedure.properties().is_generator);
        assert_eq!(
            procedure.properties().invocation,
            ProcedureInvocationKind::Deferred
        );
    }
    assert!(!stream.properties().is_async);
    assert!(stream.properties().is_generator);
    assert_eq!(
        stream.properties().invocation,
        ProcedureInvocationKind::Deferred
    );

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn rust_match_evaluates_the_subject_before_guarded_arm_selection() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "rust/match.rs",
            r#"
                fn choose() -> i32 {
                    let chosen = match inspect_subject() {
                        0 if allow_first() => first_value(),
                        99 => fallback_value(),
                    };
                    after_match(chosen)
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "rust/match.rs");
    graph
        .bind(
            "subject_normal",
            PointSelector::new("inspect_subject()")
                .procedure("choose")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "match_decision",
            PointSelector::new("match inspect_subject()")
                .procedure("choose")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "guarded_candidate",
            PointSelector::new("0 if allow_first()")
                .procedure("choose")
                .anchor_occurrence(0),
        )
        .bind(
            "fallback_candidate",
            PointSelector::new("99")
                .procedure("choose")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "guard_decision",
            PointSelector::new("allow_first()")
                .procedure("choose")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "first_arm",
            PointSelector::new("first_value()")
                .procedure("choose")
                .anchor_occurrence(0),
        )
        .bind(
            "fallback_arm",
            PointSelector::new("fallback_value()")
                .procedure("choose")
                .anchor_occurrence(0),
        )
        .bind(
            "after_match",
            PointSelector::new("after_match(chosen)")
                .procedure("choose")
                .effect("invoke"),
        );

    graph.assert_successors(
        "subject_normal",
        &[cfg_edge("match_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "match_decision",
        &[
            cfg_edge("guarded_candidate", ControlEdgeKind::SwitchCase),
            cfg_edge("fallback_candidate", ControlEdgeKind::SwitchCase),
        ],
    );
    graph.assert_successors(
        "guard_decision",
        &[
            cfg_edge("first_arm", ControlEdgeKind::ConditionalTrue),
            cfg_edge("fallback_candidate", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_point_gap(
        "match_decision",
        SemanticCapability::NormalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_reachable("subject_normal", "after_match");
    graph.assert_unreachable("match_decision", "subject_normal");
    graph.assert_adjacency_symmetric();
}

#[test]
fn rust_implicit_trait_operations_publish_exact_call_and_exception_gaps() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "rust/implicit_calls.rs",
            r#"
                fn implicit_operations(
                    left: Number,
                    right: Number,
                    values: Values,
                    index: usize,
                    holder: Holder,
                ) {
                    let _sum = left + right;
                    let _item = values[index];
                    let _negated = -make_number();
                    let _field = holder.field;
                    holder.method();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "rust/implicit_calls.rs");
    graph
        .bind(
            "binary_boundary",
            PointSelector::new("left + right")
                .procedure("implicit_operations")
                .effect("gap"),
        )
        .bind(
            "index_boundary",
            PointSelector::new("values[index]")
                .procedure("implicit_operations")
                .effect("gap"),
        )
        .bind(
            "make_number_normal",
            PointSelector::new("make_number()")
                .procedure("implicit_operations")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "unary_boundary",
            PointSelector::new("-make_number()")
                .procedure("implicit_operations")
                .effect("gap"),
        )
        .bind(
            "field_boundary",
            PointSelector::new("holder.field")
                .procedure("implicit_operations")
                .effect("gap"),
        )
        .bind(
            "method_invoke",
            PointSelector::new("holder.method()")
                .procedure("implicit_operations")
                .effect("invoke"),
        );

    graph.assert_successors(
        "make_number_normal",
        &[cfg_edge("unary_boundary", ControlEdgeKind::Normal)],
    );
    for boundary in [
        "binary_boundary",
        "index_boundary",
        "unary_boundary",
        "field_boundary",
        "method_invoke",
    ] {
        graph.assert_point_gap(
            boundary,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
        );
        graph.assert_point_gap(
            boundary,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
        );
    }
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
}

#[test]
fn rust_try_operator_routes_success_and_residual_after_operand_calls() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "rust/try_operator.rs",
            r#"
                fn propagate() -> Result<i32, Problem> {
                    let value = fallible()?;
                    after_success(value);
                    Ok(value)
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "rust/try_operator.rs");
    graph
        .bind(
            "operand_invoke",
            PointSelector::new("fallible()")
                .procedure("propagate")
                .effect("invoke"),
        )
        .bind(
            "operand_normal",
            PointSelector::new("fallible()")
                .procedure("propagate")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "try_branch",
            PointSelector::new("fallible()?")
                .procedure("propagate")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "success_binding",
            PointSelector::new("let value = fallible()?;")
                .procedure("propagate")
                .anchor_occurrence(1),
        )
        .bind(
            "residual_return",
            PointSelector::new("fallible()?")
                .procedure("propagate")
                .effect("procedure_return"),
        )
        .bind(
            "after_success",
            PointSelector::new("after_success(value)")
                .procedure("propagate")
                .effect("invoke"),
        )
        .bind(
            "normal_exit",
            PointSelector::new("fn propagate()")
                .procedure("propagate")
                .effect("normal_exit"),
        );

    graph.assert_successors(
        "operand_normal",
        &[cfg_edge("try_branch", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "try_branch",
        &[
            cfg_edge("success_binding", ControlEdgeKind::ConditionalTrue),
            cfg_edge("residual_return", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "residual_return",
        &[cfg_edge("normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "try_branch",
        SemanticCapability::NormalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "try_branch",
        SemanticCapability::Calls,
        SemanticGapKind::Unknown,
    );
    let procedure = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some("propagate")
        })
        .expect("missing Rust propagate procedure");
    let residual = procedure
        .points()
        .iter()
        .find(|point| {
            point
                .events
                .iter()
                .any(|event| matches!(event.effect, SemanticEffect::ProcedureReturn { .. }))
                && procedure.gaps().iter().any(|gap| {
                    gap.point == point.id
                        && gap.capability == SemanticCapability::CleanupControlFlow
                })
        })
        .expect("missing Rust ? residual return point");
    assert!(procedure.gaps().iter().any(|gap| {
        gap.point == residual.id
            && matches!(gap.subject, SemanticGapSubject::Value(_))
            && gap.capability == SemanticCapability::Values
            && gap.kind == SemanticGapKind::Unknown
    }));
    assert!(procedure.gaps().iter().any(|gap| {
        gap.point == residual.id
            && matches!(gap.subject, SemanticGapSubject::Value(_))
            && gap.capability == SemanticCapability::CleanupControlFlow
            && gap.kind == SemanticGapKind::Unknown
    }));
    graph.assert_reachable("operand_invoke", "after_success");
    graph.assert_unreachable("residual_return", "after_success");
    graph.assert_adjacency_symmetric();
}

#[test]
fn rust_try_block_stops_at_a_typed_boundary_without_fabricated_returns() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "rust/try_block.rs",
            r#"
                fn scoped_try() {
                    let result: Result<i32, Problem> = try {
                        inner_fallible()?;
                        1
                    };
                    after_try(result);
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "rust/try_block.rs");
    graph
        .bind(
            "entry",
            PointSelector::new("fn scoped_try()")
                .procedure("scoped_try")
                .effect("entry"),
        )
        .bind(
            "try_boundary",
            PointSelector::new(
                r#"try {
                        inner_fallible()?;
                        1
                    }"#,
            )
            .procedure("scoped_try")
            .effect("gap"),
        )
        .bind(
            "after_try",
            PointSelector::new("after_try(result)")
                .procedure("scoped_try")
                .effect("invoke"),
        )
        .bind(
            "normal_exit",
            PointSelector::new("fn scoped_try()")
                .procedure("scoped_try")
                .effect("normal_exit"),
        );

    for (capability, kind) in [
        (
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unsupported,
        ),
        (SemanticCapability::Calls, SemanticGapKind::Unknown),
        (
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
        ),
        (
            SemanticCapability::CleanupControlFlow,
            SemanticGapKind::Unknown,
        ),
        (
            SemanticCapability::ResourceManagement,
            SemanticGapKind::Unknown,
        ),
        (SemanticCapability::Values, SemanticGapKind::Unsupported),
    ] {
        graph.assert_point_gap("try_boundary", capability, kind);
    }
    graph.assert_successors("try_boundary", &[]);
    graph.assert_reachable("entry", "try_boundary");
    graph.assert_unreachable("entry", "after_try");
    graph.assert_unreachable("entry", "normal_exit");
    let error = graph
        .try_bind(
            "fabricated_inner_call",
            PointSelector::new("inner_fallible()")
                .procedure("scoped_try")
                .effect("invoke"),
        )
        .expect_err("unsupported try-block internals must not fabricate calls");
    assert!(
        error.to_string().contains("matched no semantic"),
        "unexpected try-block call selector: {error}"
    );
    graph.assert_adjacency_symmetric();
}

#[test]
fn rust_await_evaluates_its_operand_before_explicit_resume_topology() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "rust/await.rs",
            r#"
                async fn wait_one() {
                    let value = make_future().await;
                    after_await(value);
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "rust/await.rs");
    graph
        .bind(
            "future_normal",
            PointSelector::new("make_future()")
                .procedure("wait_one")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "suspend",
            PointSelector::new("make_future().await")
                .procedure("wait_one")
                .effect("async_suspend"),
        )
        .bind(
            "normal_resume",
            PointSelector::new("make_future().await")
                .procedure("wait_one")
                .effect("async_resume")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "exceptional_resume",
            PointSelector::new("make_future().await")
                .procedure("wait_one")
                .effect("async_resume")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "await_binding",
            PointSelector::new("let value = make_future().await;")
                .procedure("wait_one")
                .anchor_occurrence(1),
        )
        .bind(
            "after_await",
            PointSelector::new("after_await(value)")
                .procedure("wait_one")
                .effect("invoke"),
        )
        .bind(
            "exceptional_exit",
            PointSelector::new("async fn wait_one()")
                .procedure("wait_one")
                .effect("exceptional_exit"),
        );

    graph.assert_successors(
        "future_normal",
        &[cfg_edge("suspend", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "suspend",
        &[
            cfg_edge("normal_resume", ControlEdgeKind::AsyncNormal),
            cfg_edge("exceptional_resume", ControlEdgeKind::AsyncExceptional),
        ],
    );
    graph.assert_successors(
        "normal_resume",
        &[cfg_edge("await_binding", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "exceptional_resume",
        &[cfg_edge("exceptional_exit", ControlEdgeKind::Exceptional)],
    );
    graph.assert_point_gap(
        "suspend",
        SemanticCapability::AsyncSuspendResume,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "suspend",
        SemanticCapability::Calls,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "suspend",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    for capability in [
        SemanticCapability::ResourceManagement,
        SemanticCapability::CleanupControlFlow,
        SemanticCapability::Calls,
        SemanticCapability::ExceptionalControlFlow,
    ] {
        graph.assert_point_gap("exceptional_resume", capability, SemanticGapKind::Unknown);
    }
    graph.assert_reachable("future_normal", "after_await");
    graph.assert_unreachable("exceptional_resume", "after_await");
    graph.assert_adjacency_symmetric();
}

#[test]
fn rust_generator_yield_evaluates_its_operand_then_stops_at_the_gap() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "rust/yield.rs",
            r#"
                fn make_stream() {
                    let stream = gen move {
                        yield produce();
                        after_yield();
                    };
                    consume(stream);
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "rust/yield.rs");
    graph
        .bind(
            "stream_entry",
            PointSelector::new("gen move")
                .procedure("stream")
                .effect("entry"),
        )
        .bind(
            "produce_normal",
            PointSelector::new("produce()")
                .procedure("stream")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "yield_boundary",
            PointSelector::new("yield produce()")
                .procedure("stream")
                .effect("gap"),
        )
        .bind(
            "after_yield",
            PointSelector::new("after_yield()")
                .procedure("stream")
                .effect("invoke"),
        );

    graph.assert_successors(
        "produce_normal",
        &[cfg_edge("yield_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "yield_boundary",
        &[cfg_edge("produce_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors("yield_boundary", &[]);
    graph.assert_point_gap(
        "yield_boundary",
        SemanticCapability::GeneratorSuspension,
        SemanticGapKind::Unsupported,
    );
    graph.assert_reachable("stream_entry", "yield_boundary");
    graph.assert_unreachable("stream_entry", "after_yield");
    graph.assert_adjacency_symmetric();
}

#[test]
fn rust_macro_token_trees_are_terminal_without_fabricated_calls() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "rust/macro.rs",
            r#"
                fn opaque_macro() {
                    opaque!(hidden_call());
                    after_macro();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "rust/macro.rs");
    graph
        .bind(
            "entry",
            PointSelector::new("fn opaque_macro()")
                .procedure("opaque_macro")
                .effect("entry"),
        )
        .bind(
            "macro_boundary",
            PointSelector::new("opaque!(hidden_call())")
                .procedure("opaque_macro")
                .effect("gap"),
        )
        .bind(
            "after_macro",
            PointSelector::new("after_macro()")
                .procedure("opaque_macro")
                .effect("invoke"),
        );

    for capability in [
        SemanticCapability::NormalControlFlow,
        SemanticCapability::Calls,
        SemanticCapability::ExceptionalControlFlow,
        SemanticCapability::NonLocalControl,
        SemanticCapability::CleanupControlFlow,
        SemanticCapability::ResourceManagement,
    ] {
        graph.assert_point_gap("macro_boundary", capability, SemanticGapKind::Unsupported);
    }
    graph.assert_successors("macro_boundary", &[]);
    graph.assert_reachable("entry", "macro_boundary");
    graph.assert_unreachable("entry", "after_macro");
    let error = graph
        .try_bind(
            "fabricated_hidden_call",
            PointSelector::new("hidden_call()")
                .procedure("opaque_macro")
                .effect("invoke"),
        )
        .expect_err("macro token trees must not fabricate nested call sites");
    assert!(
        error.to_string().contains("matched no semantic"),
        "unexpected hidden macro call selector result: {error}"
    );
    graph.assert_adjacency_symmetric();
}

#[test]
fn rust_raii_scope_exit_preserves_normal_flow_with_exact_gaps() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "rust/raii.rs",
            r#"
                fn scoped_resource() {
                    before_scope();
                    {
                        let guard = acquire();
                        use_guard(&guard);
                    }
                    after_scope();
                }

                fn branch_resource(flag: bool) {
                    if flag {
                        let guard = acquire_branch();
                        use_branch(&guard);
                    }
                    after_branch();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "rust/raii.rs");
    graph
        .bind(
            "acquire_exceptional",
            PointSelector::new("acquire()")
                .procedure("scoped_resource")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "use_normal",
            PointSelector::new("use_guard(&guard)")
                .procedure("scoped_resource")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "scope_exit",
            PointSelector::new("{\n                        let guard = acquire();")
                .procedure("scoped_resource")
                .effect("gap")
                .anchor_occurrence(1),
        )
        .bind(
            "after_scope_statement",
            PointSelector::new("after_scope()")
                .procedure("scoped_resource")
                .anchor_occurrence(0),
        )
        .bind(
            "after_scope_invoke",
            PointSelector::new("after_scope()")
                .procedure("scoped_resource")
                .effect("invoke"),
        )
        .bind(
            "exceptional_exit",
            PointSelector::new("fn scoped_resource()")
                .procedure("scoped_resource")
                .effect("exceptional_exit"),
        )
        .bind(
            "branch_use_normal",
            PointSelector::new("use_branch(&guard)")
                .procedure("branch_resource")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "branch_scope_exit",
            PointSelector::new(
                r#"{
                        let guard = acquire_branch();
                        use_branch(&guard);
                    }"#,
            )
            .procedure("branch_resource")
            .effect("gap")
            .anchor_occurrence(1),
        )
        .bind(
            "after_branch_statement",
            PointSelector::new("after_branch()")
                .procedure("branch_resource")
                .anchor_occurrence(0),
        )
        .bind(
            "after_branch_invoke",
            PointSelector::new("after_branch()")
                .procedure("branch_resource")
                .effect("invoke"),
        );

    graph.assert_successors(
        "use_normal",
        &[cfg_edge("scope_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "scope_exit",
        &[cfg_edge("after_scope_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "acquire_exceptional",
        &[cfg_edge("exceptional_exit", ControlEdgeKind::Exceptional)],
    );
    for capability in [
        SemanticCapability::ResourceManagement,
        SemanticCapability::CleanupControlFlow,
        SemanticCapability::Calls,
        SemanticCapability::ExceptionalControlFlow,
    ] {
        graph.assert_point_gap("acquire_exceptional", capability, SemanticGapKind::Unknown);
    }
    graph.assert_point_gap(
        "scope_exit",
        SemanticCapability::ResourceManagement,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "scope_exit",
        SemanticCapability::CleanupControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "scope_exit",
        SemanticCapability::Calls,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "scope_exit",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_reachable("use_normal", "after_scope_invoke");
    graph.assert_unreachable("acquire_exceptional", "after_scope_invoke");
    graph.assert_successors(
        "branch_use_normal",
        &[cfg_edge("branch_scope_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "branch_scope_exit",
        &[cfg_edge("after_branch_statement", ControlEdgeKind::Normal)],
    );
    for capability in [
        SemanticCapability::ResourceManagement,
        SemanticCapability::CleanupControlFlow,
        SemanticCapability::Calls,
        SemanticCapability::ExceptionalControlFlow,
    ] {
        graph.assert_point_gap("branch_scope_exit", capability, SemanticGapKind::Unknown);
    }
    graph.assert_reachable("branch_use_normal", "after_branch_invoke");
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
}

#[test]
fn rust_raii_abrupt_exits_report_gaps_on_the_actual_transfer_points() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "rust/raii_abrupt.rs",
            r#"
                fn return_with_resource() {
                    {
                        let guard = acquire_return();
                        use_return(&guard);
                        return;
                    }
                    dead_after_return();
                }

                fn loop_with_resource(repeat: bool) {
                    loop {
                        let guard = acquire_loop();
                        use_loop(&guard);
                        if repeat {
                            continue;
                        }
                        break;
                    }
                    after_loop();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "rust/raii_abrupt.rs");
    graph
        .bind(
            "return_transfer",
            PointSelector::new("return;")
                .procedure("return_with_resource")
                .effect("procedure_return"),
        )
        .bind(
            "return_normal_exit",
            PointSelector::new("fn return_with_resource()")
                .procedure("return_with_resource")
                .effect("normal_exit"),
        )
        .bind(
            "dead_after_return",
            PointSelector::new("dead_after_return()")
                .procedure("return_with_resource")
                .effect("invoke"),
        )
        .bind(
            "loop_body",
            PointSelector::new(
                r#"{
                        let guard = acquire_loop();
                        use_loop(&guard);
                        if repeat {
                            continue;
                        }
                        break;
                    }"#,
            )
            .procedure("loop_with_resource")
            .anchor_occurrence(0),
        )
        .bind(
            "continue_transfer",
            PointSelector::new("continue;")
                .procedure("loop_with_resource")
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "break_transfer",
            PointSelector::new("break;")
                .procedure("loop_with_resource")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "after_loop",
            PointSelector::new("after_loop()")
                .procedure("loop_with_resource")
                .anchor_occurrence(0),
        );

    graph.assert_successors(
        "return_transfer",
        &[cfg_edge("return_normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_unreachable("return_transfer", "dead_after_return");
    graph.assert_successors(
        "continue_transfer",
        &[cfg_edge("loop_body", ControlEdgeKind::LoopBack)],
    );
    graph.assert_successors(
        "break_transfer",
        &[cfg_edge("after_loop", ControlEdgeKind::Normal)],
    );
    for transfer in ["return_transfer", "continue_transfer", "break_transfer"] {
        for capability in [
            SemanticCapability::ResourceManagement,
            SemanticCapability::CleanupControlFlow,
            SemanticCapability::Calls,
            SemanticCapability::ExceptionalControlFlow,
        ] {
            graph.assert_point_gap(transfer, capability, SemanticGapKind::Unknown);
        }
    }
    graph.assert_adjacency_symmetric();
}

#[test]
fn rust_parameter_pattern_and_assignment_drop_omissions_are_point_scoped() {
    let project = InlineTestProject::with_language(Language::Rust)
        .file(
            "rust/drop_bindings.rs",
            r#"
                fn drop_bindings(
                    mut parameter: Guard,
                    items: Vec<Guard>,
                    maybe: Option<Guard>,
                    stop: bool,
                ) {
                    parameter = replacement();
                    if stop {
                        return;
                    }
                    for item in items {
                        consume(item);
                        break;
                    }
                    if let Some(value) = maybe {
                        consume(value);
                    }
                    match replacement() {
                        Some(value) => consume(value),
                        None => {}
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "rust/drop_bindings.rs");
    graph
        .bind(
            "normal_exit",
            PointSelector::new("fn drop_bindings(")
                .procedure("drop_bindings")
                .effect("normal_exit"),
        )
        .bind(
            "exceptional_exit",
            PointSelector::new("fn drop_bindings(")
                .procedure("drop_bindings")
                .effect("exceptional_exit"),
        )
        .bind(
            "return",
            PointSelector::new("return;")
                .procedure("drop_bindings")
                .effect("procedure_return"),
        )
        .bind(
            "assignment",
            PointSelector::new("parameter = replacement()")
                .procedure("drop_bindings")
                .effect("gap"),
        )
        .bind(
            "for_body",
            PointSelector::new(
                r#"{
                        consume(item);
                        break;
                    }"#,
            )
            .procedure("drop_bindings")
            .effect("gap")
            .anchor_occurrence(0),
        )
        .bind(
            "for_break",
            PointSelector::new("break;")
                .procedure("drop_bindings")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "if_let_body",
            PointSelector::new(
                r#"{
                        consume(value);
                    }"#,
            )
            .procedure("drop_bindings")
            .effect("gap")
            .anchor_occurrence(0),
        )
        .bind(
            "match_pattern",
            PointSelector::new("Some(value)")
                .occurrence(1)
                .procedure("drop_bindings")
                .effect("gap")
                .anchor_occurrence(0),
        );

    for alias in [
        "normal_exit",
        "exceptional_exit",
        "return",
        "for_body",
        "for_break",
        "if_let_body",
        "match_pattern",
    ] {
        for capability in [
            SemanticCapability::ResourceManagement,
            SemanticCapability::CleanupControlFlow,
            SemanticCapability::Calls,
            SemanticCapability::ExceptionalControlFlow,
        ] {
            graph.assert_point_gap(alias, capability, SemanticGapKind::Unknown);
        }
    }
    for capability in [
        SemanticCapability::ResourceManagement,
        SemanticCapability::CleanupControlFlow,
        SemanticCapability::Calls,
        SemanticCapability::ExceptionalControlFlow,
    ] {
        graph.assert_point_gap("assignment", capability, SemanticGapKind::Unknown);
    }
    graph.assert_adjacency_symmetric();
}

#[test]
fn go_functions_methods_and_func_literals_are_distinct_immediate_procedures() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "go/callables.go",
            r#"package conformance

type Counter struct{}

func topLevel() {
    topBody()
}

func (counter *Counter) Step() {
    methodBody()
}

func outer() {
    literal := func() {
        literalBody()
    }
    _ = literal
    outerBody()
}
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "go/callables.go");
    graph
        .bind(
            "top_entry",
            PointSelector::new("func topLevel()")
                .procedure("topLevel")
                .effect("entry"),
        )
        .bind(
            "top_invoke",
            PointSelector::new("topBody()")
                .procedure("topLevel")
                .effect("invoke"),
        )
        .bind(
            "top_normal",
            PointSelector::new("topBody()")
                .procedure("topLevel")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "top_exceptional",
            PointSelector::new("topBody()")
                .procedure("topLevel")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "method_entry",
            PointSelector::new("func (counter *Counter) Step()")
                .procedure("Step")
                .effect("entry"),
        )
        .bind(
            "method_invoke",
            PointSelector::new("methodBody()")
                .procedure("Step")
                .effect("invoke"),
        )
        .bind(
            "method_normal",
            PointSelector::new("methodBody()")
                .procedure("Step")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "method_exceptional",
            PointSelector::new("methodBody()")
                .procedure("Step")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "outer_entry",
            PointSelector::new("func outer()")
                .procedure("outer")
                .effect("entry"),
        )
        .bind(
            "outer_invoke",
            PointSelector::new("outerBody()")
                .procedure("outer")
                .effect("invoke"),
        )
        .bind(
            "outer_normal",
            PointSelector::new("outerBody()")
                .procedure("outer")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "outer_exceptional",
            PointSelector::new("outerBody()")
                .procedure("outer")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "literal_entry",
            PointSelector::new("func() {")
                .procedure("literal")
                .effect("entry"),
        )
        .bind(
            "literal_invoke",
            PointSelector::new("literalBody()")
                .procedure("literal")
                .effect("invoke"),
        )
        .bind(
            "literal_normal",
            PointSelector::new("literalBody()")
                .procedure("literal")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "literal_exceptional",
            PointSelector::new("literalBody()")
                .procedure("literal")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        );

    for (entry, invoke, normal, exceptional) in [
        ("top_entry", "top_invoke", "top_normal", "top_exceptional"),
        (
            "method_entry",
            "method_invoke",
            "method_normal",
            "method_exceptional",
        ),
        (
            "outer_entry",
            "outer_invoke",
            "outer_normal",
            "outer_exceptional",
        ),
        (
            "literal_entry",
            "literal_invoke",
            "literal_normal",
            "literal_exceptional",
        ),
    ] {
        graph.assert_successors(
            invoke,
            &[
                cfg_edge(normal, ControlEdgeKind::Normal),
                cfg_edge(exceptional, ControlEdgeKind::Exceptional),
            ],
        );
        graph.assert_predecessors(normal, &[cfg_edge(invoke, ControlEdgeKind::Normal)]);
        graph.assert_predecessors(
            exceptional,
            &[cfg_edge(invoke, ControlEdgeKind::Exceptional)],
        );
        graph.assert_reachable(entry, invoke);
    }
    let error = graph
        .try_bind(
            "literal_body_in_outer",
            PointSelector::new("literalBody()")
                .procedure("outer")
                .effect("invoke"),
        )
        .expect_err("func-literal execution must remain outside the enclosing CFG");
    assert!(
        error.to_string().contains("matched no semantic"),
        "unexpected selector result: {error}"
    );

    let procedures = graph.artifact().procedures();
    let named = |name: &str, kind: ProcedureKind| {
        procedures
            .iter()
            .find(|procedure| {
                procedure.kind() == kind
                    && procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
            })
            .unwrap_or_else(|| panic!("missing Go {kind:?} procedure {name}"))
    };
    let top = named("topLevel", ProcedureKind::Function);
    let method = named("Step", ProcedureKind::Method);
    let outer = named("outer", ProcedureKind::Function);
    let literal = named("literal", ProcedureKind::Lambda);
    assert!(top.lexical_parent().is_none());
    assert!(method.lexical_parent().is_none());
    assert!(outer.lexical_parent().is_none());
    assert_eq!(literal.lexical_parent(), Some(outer.id()));
    for procedure in [top, method, outer, literal] {
        assert_eq!(
            procedure.properties().invocation,
            ProcedureInvocationKind::Immediate
        );
        assert!(!procedure.properties().is_async);
        assert!(!procedure.properties().is_generator);
    }

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn go_if_initializers_short_circuit_and_three_clause_loops_route_abrupt_flow() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "go/control.go",
            r#"package conformance

func branchFlow() {
    if ready := initIf(); ready && leftCheck() || rightCheck() {
        ifTrue()
    } else {
        ifFalse()
    }
    afterIf()
}

func loopFlow() int {
    for index := initLoop(); loopCheck(index); index = updateLoop(index) {
        if returnNow(index) {
            return finish(index)
            deadAfterReturn()
        }
        if breakNow(index) {
            break
            deadAfterBreak()
        }
        if continueNow(index) {
            continue
            deadAfterContinue()
        }
        loopBody(index)
    }
    afterLoop()
    return 0
    deadAfterFinalReturn()
}
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "go/control.go");
    graph
        .bind(
            "branch_entry",
            PointSelector::new("func branchFlow()")
                .procedure("branchFlow")
                .effect("entry"),
        )
        .bind(
            "init_if_invoke",
            PointSelector::new("initIf()")
                .procedure("branchFlow")
                .effect("invoke"),
        )
        .bind(
            "init_if_normal",
            PointSelector::new("initIf()")
                .procedure("branchFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "init_if_exceptional",
            PointSelector::new("initIf()")
                .procedure("branchFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "ready_decision",
            PointSelector::new("ready")
                .occurrence(1)
                .procedure("branchFlow")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "left_expression",
            PointSelector::new("leftCheck()")
                .procedure("branchFlow")
                .anchor_occurrence(0),
        )
        .bind(
            "left_invoke",
            PointSelector::new("leftCheck()")
                .procedure("branchFlow")
                .effect("invoke"),
        )
        .bind(
            "left_normal",
            PointSelector::new("leftCheck()")
                .procedure("branchFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "left_exceptional",
            PointSelector::new("leftCheck()")
                .procedure("branchFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "left_decision",
            PointSelector::new("leftCheck()")
                .procedure("branchFlow")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "right_expression",
            PointSelector::new("rightCheck()")
                .procedure("branchFlow")
                .anchor_occurrence(0),
        )
        .bind(
            "right_invoke",
            PointSelector::new("rightCheck()")
                .procedure("branchFlow")
                .effect("invoke"),
        )
        .bind(
            "right_normal",
            PointSelector::new("rightCheck()")
                .procedure("branchFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "right_exceptional",
            PointSelector::new("rightCheck()")
                .procedure("branchFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "right_decision",
            PointSelector::new("rightCheck()")
                .procedure("branchFlow")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "if_true_block",
            PointSelector::new("ifTrue()")
                .procedure("branchFlow")
                .anchor_occurrence(0),
        )
        .bind(
            "if_true_invoke",
            PointSelector::new("ifTrue()")
                .procedure("branchFlow")
                .effect("invoke"),
        )
        .bind(
            "if_true_normal",
            PointSelector::new("ifTrue()")
                .procedure("branchFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "if_false_block",
            PointSelector::new("ifFalse()")
                .procedure("branchFlow")
                .anchor_occurrence(0),
        )
        .bind(
            "if_false_invoke",
            PointSelector::new("ifFalse()")
                .procedure("branchFlow")
                .effect("invoke"),
        )
        .bind(
            "if_false_normal",
            PointSelector::new("ifFalse()")
                .procedure("branchFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "after_if_statement",
            PointSelector::new("afterIf()")
                .procedure("branchFlow")
                .anchor_occurrence(0),
        )
        .bind(
            "after_if_invoke",
            PointSelector::new("afterIf()")
                .procedure("branchFlow")
                .effect("invoke"),
        )
        .bind(
            "loop_entry",
            PointSelector::new("func loopFlow() int")
                .procedure("loopFlow")
                .effect("entry"),
        )
        .bind(
            "init_loop_invoke",
            PointSelector::new("initLoop()")
                .procedure("loopFlow")
                .effect("invoke"),
        )
        .bind(
            "loop_check_invoke",
            PointSelector::new("loopCheck(index)")
                .procedure("loopFlow")
                .effect("invoke"),
        )
        .bind(
            "loop_condition_entry",
            PointSelector::new("loopCheck(index)")
                .procedure("loopFlow")
                .anchor_occurrence(0),
        )
        .bind(
            "loop_check_normal",
            PointSelector::new("loopCheck(index)")
                .procedure("loopFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "loop_decision",
            PointSelector::new("loopCheck(index)")
                .procedure("loopFlow")
                .outgoing_kind(ControlEdgeKind::ConditionalFalse),
        )
        .bind(
            "update_statement",
            PointSelector::new("index = updateLoop(index)")
                .procedure("loopFlow")
                .anchor_occurrence(0),
        )
        .bind(
            "update_invoke",
            PointSelector::new("updateLoop(index)")
                .procedure("loopFlow")
                .effect("invoke"),
        )
        .bind(
            "update_normal",
            PointSelector::new("updateLoop(index)")
                .procedure("loopFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "update_boundary",
            PointSelector::new("index = updateLoop(index)")
                .procedure("loopFlow")
                .anchor_occurrence(1)
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "continue_transfer",
            PointSelector::new("continue")
                .procedure("loopFlow")
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "break_transfer",
            PointSelector::new("break")
                .procedure("loopFlow")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "return_transfer",
            PointSelector::new("return finish(index)")
                .procedure("loopFlow")
                .effect("procedure_return"),
        )
        .bind(
            "loop_normal_exit",
            PointSelector::new("func loopFlow() int")
                .procedure("loopFlow")
                .effect("normal_exit"),
        )
        .bind(
            "loop_body_invoke",
            PointSelector::new("loopBody(index)")
                .procedure("loopFlow")
                .effect("invoke"),
        )
        .bind(
            "loop_body_normal",
            PointSelector::new("loopBody(index)")
                .procedure("loopFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "after_loop_statement",
            PointSelector::new("afterLoop()")
                .procedure("loopFlow")
                .anchor_occurrence(0),
        )
        .bind(
            "after_loop_invoke",
            PointSelector::new("afterLoop()")
                .procedure("loopFlow")
                .effect("invoke"),
        )
        .bind(
            "dead_after_return",
            PointSelector::new("deadAfterReturn()")
                .procedure("loopFlow")
                .effect("invoke"),
        )
        .bind(
            "dead_after_break",
            PointSelector::new("deadAfterBreak()")
                .procedure("loopFlow")
                .effect("invoke"),
        )
        .bind(
            "dead_after_continue",
            PointSelector::new("deadAfterContinue()")
                .procedure("loopFlow")
                .effect("invoke"),
        )
        .bind(
            "dead_after_final_return",
            PointSelector::new("deadAfterFinalReturn()")
                .procedure("loopFlow")
                .effect("invoke"),
        );

    for (invoke, normal, exceptional) in [
        ("init_if_invoke", "init_if_normal", "init_if_exceptional"),
        ("left_invoke", "left_normal", "left_exceptional"),
        ("right_invoke", "right_normal", "right_exceptional"),
    ] {
        graph.assert_successors(
            invoke,
            &[
                cfg_edge(normal, ControlEdgeKind::Normal),
                cfg_edge(exceptional, ControlEdgeKind::Exceptional),
            ],
        );
    }
    graph.assert_reachable("init_if_normal", "ready_decision");
    graph.assert_successors(
        "ready_decision",
        &[
            cfg_edge("left_expression", ControlEdgeKind::ConditionalTrue),
            cfg_edge("right_expression", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "left_normal",
        &[cfg_edge("left_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "right_expression",
        &[
            cfg_edge("ready_decision", ControlEdgeKind::ConditionalFalse),
            cfg_edge("left_decision", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "right_normal",
        &[cfg_edge("right_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("left_decision", "if_true_invoke");
    graph.assert_reachable("right_decision", "if_true_invoke");
    graph.assert_reachable("right_decision", "if_false_invoke");
    graph.assert_reachable("if_true_block", "if_true_invoke");
    graph.assert_reachable("if_false_block", "if_false_invoke");
    graph.assert_successors(
        "if_true_normal",
        &[cfg_edge("after_if_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "if_false_normal",
        &[cfg_edge("after_if_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "after_if_statement",
        &[
            cfg_edge("if_true_normal", ControlEdgeKind::Normal),
            cfg_edge("if_false_normal", ControlEdgeKind::Normal),
        ],
    );
    graph.assert_reachable("branch_entry", "after_if_invoke");

    graph.assert_reachable("init_loop_invoke", "loop_check_invoke");
    graph.assert_successors(
        "loop_check_normal",
        &[cfg_edge("loop_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("loop_decision", "loop_body_invoke");
    graph.assert_successors(
        "continue_transfer",
        &[cfg_edge("update_statement", ControlEdgeKind::LoopBack)],
    );
    graph.assert_successors(
        "loop_body_normal",
        &[cfg_edge("update_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("update_statement", "update_invoke");
    graph.assert_successors(
        "update_normal",
        &[cfg_edge("update_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "update_boundary",
        &[cfg_edge("loop_condition_entry", ControlEdgeKind::LoopBack)],
    );
    graph.assert_reachable("loop_condition_entry", "loop_check_invoke");
    graph.assert_successors(
        "break_transfer",
        &[cfg_edge("after_loop_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "return_transfer",
        &[cfg_edge("loop_normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("loop_entry", "after_loop_invoke");
    for dead in [
        "dead_after_return",
        "dead_after_break",
        "dead_after_continue",
        "dead_after_final_return",
    ] {
        graph.assert_unreachable("loop_entry", dead);
    }

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn go_defer_and_spawn_evaluate_operands_without_immediate_target_calls() {
    const SOURCE: &str = r#"package conformance

func deferredTarget(value int) {}
func spawnedTarget(value int) {}

func makeDeferred() func(int) { return deferredTarget }
func makeSpawned() func(int) { return spawnedTarget }
func deferredArg() int { return 1 }
func spawnedArg() int { return 2 }
func between() {}
func afterSchedule() {}

func schedule() {
    defer makeDeferred()(deferredArg())
    between()
    go makeSpawned()(spawnedArg())
    afterSchedule()
}
"#;
    let project = InlineTestProject::with_language(Language::Go)
        .file("go/scheduling.go", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "go/scheduling.go");
    graph
        .bind(
            "schedule_entry",
            PointSelector::new("func schedule()")
                .procedure("schedule")
                .effect("entry"),
        )
        .bind(
            "make_deferred_invoke",
            PointSelector::new("makeDeferred()")
                .procedure("schedule")
                .effect("invoke"),
        )
        .bind(
            "make_deferred_normal",
            PointSelector::new("makeDeferred()")
                .procedure("schedule")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "make_deferred_exceptional",
            PointSelector::new("makeDeferred()")
                .procedure("schedule")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "deferred_arg_expression",
            PointSelector::new("deferredArg()")
                .procedure("schedule")
                .anchor_occurrence(0),
        )
        .bind(
            "deferred_arg_invoke",
            PointSelector::new("deferredArg()")
                .procedure("schedule")
                .effect("invoke"),
        )
        .bind(
            "deferred_arg_normal",
            PointSelector::new("deferredArg()")
                .procedure("schedule")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "deferred_arg_exceptional",
            PointSelector::new("deferredArg()")
                .procedure("schedule")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "defer_boundary",
            PointSelector::new("defer ")
                .procedure("schedule")
                .effect("gap"),
        )
        .bind(
            "between_statement",
            PointSelector::new("between()")
                .procedure("schedule")
                .anchor_occurrence(0),
        )
        .bind(
            "between_invoke",
            PointSelector::new("between()")
                .procedure("schedule")
                .effect("invoke"),
        )
        .bind(
            "between_normal",
            PointSelector::new("between()")
                .procedure("schedule")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "make_spawned_expression",
            PointSelector::new("makeSpawned()")
                .procedure("schedule")
                .anchor_occurrence(0),
        )
        .bind(
            "spawn_statement",
            PointSelector::new("go makeSpawned()(spawnedArg())")
                .procedure("schedule")
                .anchor_occurrence(0),
        )
        .bind(
            "make_spawned_invoke",
            PointSelector::new("makeSpawned()")
                .procedure("schedule")
                .effect("invoke"),
        )
        .bind(
            "make_spawned_normal",
            PointSelector::new("makeSpawned()")
                .procedure("schedule")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "make_spawned_exceptional",
            PointSelector::new("makeSpawned()")
                .procedure("schedule")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "spawned_arg_expression",
            PointSelector::new("spawnedArg()")
                .procedure("schedule")
                .anchor_occurrence(0),
        )
        .bind(
            "spawned_arg_invoke",
            PointSelector::new("spawnedArg()")
                .procedure("schedule")
                .effect("invoke"),
        )
        .bind(
            "spawned_arg_normal",
            PointSelector::new("spawnedArg()")
                .procedure("schedule")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "spawned_arg_exceptional",
            PointSelector::new("spawnedArg()")
                .procedure("schedule")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "spawn_boundary",
            PointSelector::new("go makeSpawned")
                .procedure("schedule")
                .effect("gap"),
        )
        .bind(
            "after_schedule_statement",
            PointSelector::new("afterSchedule()")
                .procedure("schedule")
                .anchor_occurrence(0),
        )
        .bind(
            "after_schedule_invoke",
            PointSelector::new("afterSchedule()")
                .procedure("schedule")
                .effect("invoke"),
        );

    for (invoke, normal, exceptional) in [
        (
            "make_deferred_invoke",
            "make_deferred_normal",
            "make_deferred_exceptional",
        ),
        (
            "deferred_arg_invoke",
            "deferred_arg_normal",
            "deferred_arg_exceptional",
        ),
        (
            "make_spawned_invoke",
            "make_spawned_normal",
            "make_spawned_exceptional",
        ),
        (
            "spawned_arg_invoke",
            "spawned_arg_normal",
            "spawned_arg_exceptional",
        ),
    ] {
        graph.assert_successors(
            invoke,
            &[
                cfg_edge(normal, ControlEdgeKind::Normal),
                cfg_edge(exceptional, ControlEdgeKind::Exceptional),
            ],
        );
    }
    graph.assert_successors(
        "make_deferred_normal",
        &[cfg_edge("deferred_arg_expression", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "deferred_arg_expression",
        &[cfg_edge("make_deferred_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "deferred_arg_normal",
        &[cfg_edge("defer_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "defer_boundary",
        &[cfg_edge("deferred_arg_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "defer_boundary",
        SemanticCapability::DeferredExecution,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "defer_boundary",
        SemanticCapability::CleanupControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors(
        "defer_boundary",
        &[cfg_edge("between_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "between_normal",
        &[cfg_edge("spawn_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "spawn_statement",
        &[cfg_edge("make_spawned_expression", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "make_spawned_normal",
        &[cfg_edge("spawned_arg_expression", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "spawned_arg_expression",
        &[cfg_edge("make_spawned_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "spawned_arg_normal",
        &[cfg_edge("spawn_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "spawn_boundary",
        &[cfg_edge("spawned_arg_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "spawn_boundary",
        SemanticCapability::ConcurrentSpawn,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors(
        "spawn_boundary",
        &[cfg_edge(
            "after_schedule_statement",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_reachable("schedule_entry", "after_schedule_invoke");

    let schedule = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some("schedule")
        })
        .expect("missing Go schedule procedure");
    let snippet = |start: u32, end: u32| {
        SOURCE
            .get(start as usize..end as usize)
            .expect("semantic source mapping should index the inline Go source")
    };
    let mut call_texts = schedule
        .call_sites()
        .iter()
        .map(|call| {
            let span = schedule
                .source_mapping(call.source)
                .expect("validated Go call site should retain its source mapping")
                .locator
                .anchor()
                .span();
            snippet(span.start_byte(), span.end_byte())
        })
        .collect::<Vec<_>>();
    call_texts.sort_unstable();
    assert_eq!(
        call_texts,
        vec![
            "afterSchedule()",
            "between()",
            "deferredArg()",
            "makeDeferred()",
            "makeSpawned()",
            "spawnedArg()",
        ]
    );
    let mut invoke_texts = schedule
        .points()
        .iter()
        .filter(|point| {
            point
                .events
                .iter()
                .any(|event| matches!(event.effect, SemanticEffect::Invoke { .. }))
        })
        .map(|point| {
            let span = schedule
                .source_mapping(point.source)
                .expect("validated Go invoke point should retain its source mapping")
                .locator
                .anchor()
                .span();
            snippet(span.start_byte(), span.end_byte())
        })
        .collect::<Vec<_>>();
    invoke_texts.sort_unstable();
    assert_eq!(invoke_texts, call_texts);
    assert!(!call_texts.contains(&"makeDeferred()(deferredArg())"));
    assert!(!call_texts.contains(&"makeSpawned()(spawnedArg())"));

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));

    let mut icfg = IcfgGraph::materialize(
        &project,
        &analyzer,
        "go/scheduling.go",
        PointSelector::new("func schedule()")
            .procedure("schedule")
            .effect("entry"),
    );
    icfg.bind_node(
        "icfg_schedule_entry",
        "go/scheduling.go",
        PointSelector::new("func schedule()")
            .procedure("schedule")
            .effect("entry"),
        root(),
    )
    .bind_node(
        "icfg_after_schedule",
        "go/scheduling.go",
        PointSelector::new("afterSchedule()")
            .procedure("schedule")
            .effect("invoke"),
        root(),
    );
    for target in ["deferredTarget", "spawnedTarget"] {
        let error = icfg
            .try_bind_node(
                format!("unexpected_{target}_entry"),
                "go/scheduling.go",
                PointSelector::new(format!("func {target}(value int)"))
                    .procedure(target)
                    .effect("entry"),
                root(),
            )
            .expect_err("defer/go target body must not be entered as an immediate call");
        assert!(error.to_string().contains("matched 0 snapshot node"));
    }
    icfg.assert_outcome(IcfgOutcomeKind::Complete);
    icfg.assert_reachable("icfg_schedule_entry", "icfg_after_schedule");
    icfg.assert_adjacency_symmetric();
    let rendered = icfg.render_topology();
    assert_eq!(rendered, icfg.render_topology());
    assert!(!rendered.contains("IcfgNodeId"));
    assert!(!rendered.contains("IcfgEdgeId"));
}

#[test]
fn go_range_evaluates_source_once_and_runtime_targets_each_iteration() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "go/range.go",
            r#"package conformance

func rangeFlow(sink []int) {
    for sink[index()] = range source() {
        rangeBody()
    }
    afterRange()
}
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "go/range.go");
    graph
        .bind(
            "entry",
            PointSelector::new("func rangeFlow(sink []int)")
                .procedure("rangeFlow")
                .effect("entry"),
        )
        .bind(
            "source_invoke",
            PointSelector::new("source()")
                .procedure("rangeFlow")
                .effect("invoke"),
        )
        .bind(
            "source_normal",
            PointSelector::new("source()")
                .procedure("rangeFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "source_exceptional",
            PointSelector::new("source()")
                .procedure("rangeFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "range_dispatch",
            PointSelector::new("for sink[index()] = range source()")
                .procedure("rangeFlow")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "target_entry",
            PointSelector::new("sink[index()]")
                .procedure("rangeFlow")
                .anchor_occurrence(0),
        )
        .bind(
            "target_evaluation",
            PointSelector::new("sink[index()]")
                .procedure("rangeFlow")
                .effect("gap")
                .anchor_occurrence(2),
        )
        .bind(
            "index_invoke",
            PointSelector::new("index()")
                .procedure("rangeFlow")
                .effect("invoke"),
        )
        .bind(
            "index_normal",
            PointSelector::new("index()")
                .procedure("rangeFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "index_exceptional",
            PointSelector::new("index()")
                .procedure("rangeFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "target_binding",
            PointSelector::new("sink[index()]")
                .procedure("rangeFlow")
                .effect("gap")
                .anchor_occurrence(1)
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "body_block",
            PointSelector::new("rangeBody()")
                .procedure("rangeFlow")
                .anchor_occurrence(0),
        )
        .bind(
            "body_invoke",
            PointSelector::new("rangeBody()")
                .procedure("rangeFlow")
                .effect("invoke"),
        )
        .bind(
            "body_normal",
            PointSelector::new("rangeBody()")
                .procedure("rangeFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "after_statement",
            PointSelector::new("afterRange()")
                .procedure("rangeFlow")
                .anchor_occurrence(0),
        )
        .bind(
            "after_invoke",
            PointSelector::new("afterRange()")
                .procedure("rangeFlow")
                .effect("invoke"),
        );

    graph.assert_successors(
        "source_invoke",
        &[
            cfg_edge("source_normal", ControlEdgeKind::Normal),
            cfg_edge("source_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "source_normal",
        &[cfg_edge("range_dispatch", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "range_dispatch",
        &[
            cfg_edge("source_normal", ControlEdgeKind::Normal),
            cfg_edge("body_normal", ControlEdgeKind::LoopBack),
        ],
    );
    graph.assert_point_gap(
        "range_dispatch",
        SemanticCapability::Calls,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "range_dispatch",
        SemanticCapability::NormalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_successors(
        "range_dispatch",
        &[
            cfg_edge("target_entry", ControlEdgeKind::ConditionalTrue),
            cfg_edge("after_statement", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_predecessors(
        "target_entry",
        &[cfg_edge("range_dispatch", ControlEdgeKind::ConditionalTrue)],
    );
    graph.assert_successors(
        "target_entry",
        &[cfg_edge("target_evaluation", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("target_evaluation", "index_invoke");
    graph.assert_successors(
        "index_invoke",
        &[
            cfg_edge("index_normal", ControlEdgeKind::Normal),
            cfg_edge("index_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "index_normal",
        &[cfg_edge("target_binding", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "target_binding",
        SemanticCapability::Calls,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "target_binding",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_reachable("target_binding", "body_invoke");
    graph.assert_successors(
        "body_normal",
        &[cfg_edge("range_dispatch", ControlEdgeKind::LoopBack)],
    );
    graph.assert_predecessors(
        "after_statement",
        &[cfg_edge(
            "range_dispatch",
            ControlEdgeKind::ConditionalFalse,
        )],
    );
    graph.assert_reachable("entry", "after_invoke");
    graph.assert_unreachable("after_statement", "source_invoke");

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn go_switch_goto_and_select_stop_at_typed_boundaries() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "go/boundaries.go",
            r#"package conformance

func switchFlow() {
    switch selector() {
    case 0:
        firstCase()
        fallthrough
    case 1:
        secondCase()
    default:
        defaultCase()
    }
    afterSwitch()
}

func gotoFlow() {
    beforeGoto()
    goto Target
    deadAfterGoto()
Target:
    targetBody()
}

func selectFlow(channel chan int) {
    select {
    case <-channel:
        selectedCase()
    default:
        selectedDefault()
    }
    afterSelect()
}
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "go/boundaries.go");
    graph
        .bind(
            "switch_entry",
            PointSelector::new("func switchFlow()")
                .procedure("switchFlow")
                .effect("entry"),
        )
        .bind(
            "selector_invoke",
            PointSelector::new("selector()")
                .procedure("switchFlow")
                .effect("invoke"),
        )
        .bind(
            "selector_normal",
            PointSelector::new("selector()")
                .procedure("switchFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "selector_exceptional",
            PointSelector::new("selector()")
                .procedure("switchFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "switch_boundary",
            PointSelector::new("case 0:")
                .procedure("switchFlow")
                .effect("gap"),
        )
        .bind(
            "after_switch",
            PointSelector::new("afterSwitch()")
                .procedure("switchFlow")
                .effect("invoke"),
        )
        .bind(
            "goto_entry",
            PointSelector::new("func gotoFlow()")
                .procedure("gotoFlow")
                .effect("entry"),
        )
        .bind(
            "before_goto_invoke",
            PointSelector::new("beforeGoto()")
                .procedure("gotoFlow")
                .effect("invoke"),
        )
        .bind(
            "before_goto_normal",
            PointSelector::new("beforeGoto()")
                .procedure("gotoFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "goto_boundary",
            PointSelector::new("goto Target")
                .procedure("gotoFlow")
                .effect("gap"),
        )
        .bind(
            "dead_after_goto",
            PointSelector::new("deadAfterGoto()")
                .procedure("gotoFlow")
                .effect("invoke"),
        )
        .bind(
            "target_body",
            PointSelector::new("targetBody()")
                .procedure("gotoFlow")
                .effect("invoke"),
        )
        .bind(
            "select_entry",
            PointSelector::new("func selectFlow(channel chan int)")
                .procedure("selectFlow")
                .effect("entry"),
        )
        .bind(
            "select_boundary",
            PointSelector::new("default:\n        selectedDefault()")
                .procedure("selectFlow")
                .effect("gap"),
        )
        .bind(
            "after_select",
            PointSelector::new("afterSelect()")
                .procedure("selectFlow")
                .effect("invoke"),
        );

    graph.assert_successors(
        "selector_invoke",
        &[
            cfg_edge("selector_normal", ControlEdgeKind::Normal),
            cfg_edge("selector_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "selector_normal",
        &[cfg_edge("switch_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "switch_boundary",
        &[cfg_edge("selector_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "switch_boundary",
        SemanticCapability::NormalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "switch_boundary",
        SemanticCapability::Calls,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "switch_boundary",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_successors("switch_boundary", &[]);
    graph.assert_reachable("switch_entry", "switch_boundary");
    graph.assert_unreachable("switch_entry", "after_switch");
    for deferred_case_call in ["firstCase()", "secondCase()", "defaultCase()"] {
        let error = graph
            .try_bind(
                format!("unscheduled_{deferred_case_call}"),
                PointSelector::new(deferred_case_call)
                    .procedure("switchFlow")
                    .effect("invoke"),
            )
            .expect_err("unsupported switch cases must not be guessed");
        assert!(error.to_string().contains("matched no semantic"));
    }

    graph.assert_successors(
        "before_goto_normal",
        &[cfg_edge("goto_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "goto_boundary",
        &[cfg_edge("before_goto_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "goto_boundary",
        SemanticCapability::NonLocalControl,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors("goto_boundary", &[]);
    graph.assert_reachable("goto_entry", "before_goto_invoke");
    graph.assert_unreachable("goto_entry", "dead_after_goto");
    graph.assert_unreachable("goto_entry", "target_body");

    graph.assert_point_gap(
        "select_boundary",
        SemanticCapability::NormalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "select_boundary",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_successors("select_boundary", &[]);
    graph.assert_reachable("select_entry", "select_boundary");
    graph.assert_unreachable("select_entry", "after_select");
    for deferred_case_call in ["selectedCase()", "selectedDefault()"] {
        let error = graph
            .try_bind(
                format!("unscheduled_{deferred_case_call}"),
                PointSelector::new(deferred_case_call)
                    .procedure("selectFlow")
                    .effect("invoke"),
            )
            .expect_err("unsupported select cases must not be guessed");
        assert!(error.to_string().contains("matched no semantic"));
    }

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn go_select_selected_receive_lhs_and_case_bodies_are_not_fabricated() {
    const SOURCE: &str = r#"package conformance

func selectAssignment(channel chan int, sink []int) {
    select {
    case sink[index()] = <-channel:
        selectedCase()
    default:
        selectedDefault()
    }
    afterSelectAssignment()
}
"#;
    let project = InlineTestProject::with_language(Language::Go)
        .file("go/select_assignment.go", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "go/select_assignment.go");
    graph
        .bind(
            "entry",
            PointSelector::new("func selectAssignment(channel chan int, sink []int)")
                .procedure("selectAssignment")
                .effect("entry"),
        )
        .bind(
            "select_boundary",
            PointSelector::new("select {\n    case sink[index()] = <-channel:")
                .procedure("selectAssignment")
                .effect("gap"),
        )
        .bind(
            "after_select",
            PointSelector::new("afterSelectAssignment()")
                .procedure("selectAssignment")
                .effect("invoke"),
        );

    graph.assert_point_gap(
        "select_boundary",
        SemanticCapability::Calls,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "select_boundary",
        SemanticCapability::NormalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "select_boundary",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_successors("select_boundary", &[]);
    graph.assert_reachable("entry", "select_boundary");
    graph.assert_unreachable("entry", "after_select");

    for selected_only_call in ["index()", "selectedCase()", "selectedDefault()"] {
        let error = graph
            .try_bind(
                format!("fabricated_{selected_only_call}"),
                PointSelector::new(selected_only_call)
                    .procedure("selectAssignment")
                    .effect("invoke"),
            )
            .expect_err("selected-only select work must not be fabricated as eager control flow");
        assert!(error.to_string().contains("matched no semantic"));
    }

    let procedure = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some("selectAssignment")
        })
        .expect("missing Go selectAssignment procedure");
    let mut call_texts = procedure
        .call_sites()
        .iter()
        .map(|call| {
            let span = procedure
                .source_mapping(call.source)
                .expect("validated Go call site should retain its source mapping")
                .locator
                .anchor()
                .span();
            SOURCE
                .get(span.start_byte() as usize..span.end_byte() as usize)
                .expect("semantic source mapping should index the inline Go source")
        })
        .collect::<Vec<_>>();
    call_texts.sort_unstable();
    assert_eq!(call_texts, vec!["afterSelectAssignment()"]);

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn go_unspecified_composite_element_order_is_an_explicit_gap() {
    let project = InlineTestProject::with_language(Language::Go)
        .file(
            "go/unspecified_order.go",
            r#"package conformance

func mutate() int { return 1 }
func first() int { return 1 }
func second() int { return 2 }

func unspecifiedOrder(pointer *int) []int {
    values := []int{*pointer, mutate()}
    return values
}

func specifiedCallOrder() []int {
    return []int{first(), second()}
}
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "go/unspecified_order.go");
    graph
        .bind(
            "entry",
            PointSelector::new("func unspecifiedOrder(pointer *int) []int")
                .procedure("unspecifiedOrder")
                .effect("entry"),
        )
        .bind(
            "order_gap",
            PointSelector::new("[]int{*pointer, mutate()}")
                .procedure("unspecifiedOrder")
                .effect("gap")
                .anchor_occurrence(0),
        )
        .bind(
            "mutate_invoke",
            PointSelector::new("mutate()")
                .procedure("unspecifiedOrder")
                .effect("invoke"),
        )
        .bind(
            "mutate_normal",
            PointSelector::new("mutate()")
                .procedure("unspecifiedOrder")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "mutate_exceptional",
            PointSelector::new("mutate()")
                .procedure("unspecifiedOrder")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        );

    graph.assert_point_gap(
        "order_gap",
        SemanticCapability::NormalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_successors(
        "mutate_invoke",
        &[
            cfg_edge("mutate_normal", ControlEdgeKind::Normal),
            cfg_edge("mutate_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_reachable("entry", "mutate_invoke");

    let error = graph
        .try_bind(
            "specified_call_order_gap",
            PointSelector::new("[]int{first(), second()}")
                .procedure("specifiedCallOrder")
                .effect("gap")
                .anchor_occurrence(0),
        )
        .expect_err("Go's lexical ordering of call-only evaluation must remain exact");
    assert!(
        error.to_string().contains("matched no semantic"),
        "unexpected selector result: {error}"
    );

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn go_shadowed_panic_and_recover_remain_ordinary_location_first_calls() {
    const SOURCE: &str = r#"package conformance

func panic(value int) int { return value }
func recover() int { return 7 }

func shadowBuiltins() int {
    return panic(recover())
}
"#;
    let project = InlineTestProject::with_language(Language::Go)
        .file("go/shadowed_builtins.go", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "go/shadowed_builtins.go");
    graph
        .bind(
            "caller_entry",
            PointSelector::new("func shadowBuiltins() int")
                .procedure("shadowBuiltins")
                .effect("entry"),
        )
        .bind(
            "recover_invoke",
            PointSelector::new("recover()")
                .procedure("shadowBuiltins")
                .effect("invoke"),
        )
        .bind(
            "recover_normal",
            PointSelector::new("recover()")
                .procedure("shadowBuiltins")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "recover_exceptional",
            PointSelector::new("recover()")
                .procedure("shadowBuiltins")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "panic_invoke",
            PointSelector::new("panic(recover())")
                .procedure("shadowBuiltins")
                .effect("invoke"),
        )
        .bind(
            "panic_normal",
            PointSelector::new("panic(recover())")
                .procedure("shadowBuiltins")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "panic_exceptional",
            PointSelector::new("panic(recover())")
                .procedure("shadowBuiltins")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        );

    graph.assert_successors(
        "recover_invoke",
        &[
            cfg_edge("recover_normal", ControlEdgeKind::Normal),
            cfg_edge("recover_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "panic_invoke",
        &[
            cfg_edge("panic_normal", ControlEdgeKind::Normal),
            cfg_edge("panic_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_reachable("recover_normal", "panic_invoke");
    graph.assert_reachable("caller_entry", "panic_normal");

    let caller = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some("shadowBuiltins")
        })
        .expect("missing Go shadowBuiltins procedure");
    for expected_source in ["panic(recover())", "recover()"] {
        let call = caller
            .call_sites()
            .iter()
            .find(|call| {
                let span = caller
                    .source_mapping(call.source)
                    .expect("validated Go call site should retain its source mapping")
                    .locator
                    .anchor()
                    .span();
                SOURCE.get(span.start_byte() as usize..span.end_byte() as usize)
                    == Some(expected_source)
            })
            .unwrap_or_else(|| panic!("missing ordinary Go call site for {expected_source}"));
        assert!(matches!(
            call.declared_targets,
            CallableTargetResolution::Unknown
        ));
        let point = caller
            .point(call.point)
            .expect("call-site point should remain in its procedure");
        let gaps = point
            .events
            .iter()
            .filter_map(|event| match &event.effect {
                SemanticEffect::Gap { gap } => caller.gap(*gap),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(gaps.iter().any(|gap| {
            gap.subject == SemanticGapSubject::Value(call.callee)
                && gap.capability == SemanticCapability::CallableReferences
                && gap.kind == SemanticGapKind::Unknown
        }));
        assert!(gaps.iter().any(|gap| {
            gap.subject == SemanticGapSubject::CallSite(call.id)
                && gap.capability == SemanticCapability::Calls
                && gap.kind == SemanticGapKind::Unknown
        }));
    }

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));

    let mut icfg = IcfgGraph::materialize(
        &project,
        &analyzer,
        "go/shadowed_builtins.go",
        PointSelector::new("func shadowBuiltins() int")
            .procedure("shadowBuiltins")
            .effect("entry"),
    );
    icfg.bind_call(
        "recover_call",
        "go/shadowed_builtins.go",
        PointSelector::new("recover()")
            .procedure("shadowBuiltins")
            .effect("invoke"),
    )
    .bind_call(
        "panic_call",
        "go/shadowed_builtins.go",
        PointSelector::new("panic(recover())")
            .procedure("shadowBuiltins")
            .effect("invoke"),
    )
    .bind_node(
        "icfg_recover_invoke",
        "go/shadowed_builtins.go",
        PointSelector::new("recover()")
            .procedure("shadowBuiltins")
            .effect("invoke"),
        root(),
    )
    .bind_node(
        "recover_entry",
        "go/shadowed_builtins.go",
        PointSelector::new("func recover() int")
            .procedure("recover")
            .effect("entry"),
        ["recover_call"],
    )
    .bind_node(
        "recover_exit",
        "go/shadowed_builtins.go",
        PointSelector::new("func recover() int")
            .procedure("recover")
            .effect("normal_exit"),
        ["recover_call"],
    )
    .bind_node(
        "recover_continuation",
        "go/shadowed_builtins.go",
        PointSelector::new("recover()")
            .procedure("shadowBuiltins")
            .effect("call_continuation")
            .outgoing_kind(ControlEdgeKind::Normal),
        root(),
    )
    .bind_node(
        "icfg_panic_invoke",
        "go/shadowed_builtins.go",
        PointSelector::new("panic(recover())")
            .procedure("shadowBuiltins")
            .effect("invoke"),
        root(),
    )
    .bind_node(
        "panic_entry",
        "go/shadowed_builtins.go",
        PointSelector::new("func panic(value int) int")
            .procedure("panic")
            .effect("entry"),
        ["panic_call"],
    )
    .bind_node(
        "panic_exit",
        "go/shadowed_builtins.go",
        PointSelector::new("func panic(value int) int")
            .procedure("panic")
            .effect("normal_exit"),
        ["panic_call"],
    )
    .bind_node(
        "panic_continuation",
        "go/shadowed_builtins.go",
        PointSelector::new("panic(recover())")
            .procedure("shadowBuiltins")
            .effect("call_continuation")
            .outgoing_kind(ControlEdgeKind::Normal),
        root(),
    );

    icfg.assert_outcome(IcfgOutcomeKind::Complete);
    icfg.assert_successors(
        "icfg_recover_invoke",
        &[icfg_edge("recover_entry", IcfgEdgeKind::Call).originating_call("recover_call")],
    );
    icfg.assert_successors(
        "recover_exit",
        &[
            icfg_edge("recover_continuation", IcfgEdgeKind::NormalReturn)
                .originating_call("recover_call"),
        ],
    );
    icfg.assert_successors(
        "icfg_panic_invoke",
        &[icfg_edge("panic_entry", IcfgEdgeKind::Call).originating_call("panic_call")],
    );
    icfg.assert_successors(
        "panic_exit",
        &[icfg_edge("panic_continuation", IcfgEdgeKind::NormalReturn)
            .originating_call("panic_call")],
    );
    icfg.assert_adjacency_symmetric();
    let rendered = icfg.render_topology();
    assert_eq!(rendered, icfg.render_topology());
    assert!(!rendered.contains("IcfgNodeId"));
    assert!(!rendered.contains("IcfgEdgeId"));
}

#[test]
fn csharp_direct_call_conformance() {
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::CSharp,
        dialect: SemanticLanguage::Standard(Language::CSharp),
        callee_path: "csharp/Conformance/CSharpLibrary.cs",
        callee_source: r#"
            namespace Conformance
            {
                public static class CSharpLibrary
                {
                    public static int CSharpLeaf()
                    {
                        return 7;
                    }
                }
            }
        "#,
        callee_declaration: "public static int CSharpLeaf()",
        callee_name: "CSharpLeaf",
        caller_path: "csharp/Conformance/CSharpCaller.cs",
        caller_source: r#"
            namespace Conformance
            {
                public static class CSharpCaller
                {
                    public static int CSharpRoot()
                    {
                        return CSharpLibrary.CSharpLeaf();
                    }
                }
            }
        "#,
        caller_declaration: "public static int CSharpRoot()",
        caller_name: "CSharpRoot",
        call: "CSharpLibrary.CSharpLeaf()",
    });
}

#[test]
fn python_direct_call_conformance() {
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::Python,
        dialect: SemanticLanguage::Standard(Language::Python),
        callee_path: "library.py",
        callee_source: r#"def python_leaf():
    return 7
"#,
        callee_declaration: "def python_leaf()",
        callee_name: "python_leaf",
        caller_path: "caller.py",
        caller_source: r#"from library import python_leaf

def python_root():
    return python_leaf()
"#,
        caller_declaration: "def python_root()",
        caller_name: "python_root",
        call: "python_leaf()",
    });
}

#[test]
fn python_deferred_callables_are_icfg_boundaries_not_immediate_entries() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "deferred_library.py",
            r#"async def async_leaf():
    return 1

def generator_leaf():
    yield 2
"#,
        )
        .file(
            "deferred_caller.py",
            r#"from deferred_library import async_leaf, generator_leaf

def make_deferred():
    pending = async_leaf()
    stream = generator_leaf()
    return pending, stream
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "deferred_caller.py",
        PointSelector::new("def make_deferred():")
            .procedure("make_deferred")
            .effect("entry"),
    );
    graph
        .bind_call(
            "async_call",
            "deferred_caller.py",
            PointSelector::new("async_leaf()")
                .procedure("make_deferred")
                .effect("invoke"),
        )
        .bind_call(
            "generator_call",
            "deferred_caller.py",
            PointSelector::new("generator_leaf()")
                .procedure("make_deferred")
                .effect("invoke"),
        )
        .bind_node(
            "deferred_caller_entry",
            "deferred_caller.py",
            PointSelector::new("def make_deferred():")
                .procedure("make_deferred")
                .effect("entry"),
            root(),
        )
        .bind_node(
            "async_invoke",
            "deferred_caller.py",
            PointSelector::new("async_leaf()")
                .procedure("make_deferred")
                .effect("invoke"),
            root(),
        )
        .bind_node(
            "async_normal",
            "deferred_caller.py",
            PointSelector::new("async_leaf()")
                .procedure("make_deferred")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
            root(),
        )
        .bind_node(
            "async_exceptional",
            "deferred_caller.py",
            PointSelector::new("async_leaf()")
                .procedure("make_deferred")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
            root(),
        )
        .bind_node(
            "generator_invoke",
            "deferred_caller.py",
            PointSelector::new("generator_leaf()")
                .procedure("make_deferred")
                .effect("invoke"),
            root(),
        )
        .bind_node(
            "generator_normal",
            "deferred_caller.py",
            PointSelector::new("generator_leaf()")
                .procedure("make_deferred")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
            root(),
        )
        .bind_node(
            "generator_exceptional",
            "deferred_caller.py",
            PointSelector::new("generator_leaf()")
                .procedure("make_deferred")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
            root(),
        );

    graph.assert_outcome(IcfgOutcomeKind::Complete);
    graph.assert_boundary(
        "async_invoke",
        ExpectedIcfgBoundary::new(ExpectedIcfgBoundaryKind::DispatchDeferred(
            DeferredInvocationKind::Async,
        ))
        .originating_call("async_call"),
    );
    graph.assert_successors(
        "async_invoke",
        &[
            icfg_edge("async_normal", IcfgEdgeKind::CallToNormalContinuation)
                .originating_call("async_call"),
            icfg_edge(
                "async_exceptional",
                IcfgEdgeKind::CallToExceptionalContinuation,
            )
            .originating_call("async_call"),
        ],
    );
    graph.assert_predecessors(
        "async_normal",
        &[
            icfg_edge("async_invoke", IcfgEdgeKind::CallToNormalContinuation)
                .originating_call("async_call"),
        ],
    );
    graph.assert_boundary(
        "generator_invoke",
        ExpectedIcfgBoundary::new(ExpectedIcfgBoundaryKind::DispatchDeferred(
            DeferredInvocationKind::Generator,
        ))
        .originating_call("generator_call"),
    );
    graph.assert_successors(
        "generator_invoke",
        &[
            icfg_edge("generator_normal", IcfgEdgeKind::CallToNormalContinuation)
                .originating_call("generator_call"),
            icfg_edge(
                "generator_exceptional",
                IcfgEdgeKind::CallToExceptionalContinuation,
            )
            .originating_call("generator_call"),
        ],
    );
    graph.assert_predecessors(
        "generator_normal",
        &[
            icfg_edge("generator_invoke", IcfgEdgeKind::CallToNormalContinuation)
                .originating_call("generator_call"),
        ],
    );
    graph.assert_reachable("deferred_caller_entry", "generator_normal");
    graph.assert_unreachable("generator_invoke", "async_invoke");
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("IcfgNodeId"));
    assert!(!rendered.contains("IcfgEdgeId"));
}

#[test]
fn typescript_direct_call_conformance() {
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::TypeScript,
        dialect: SemanticLanguage::Standard(Language::TypeScript),
        callee_path: "ts/leaf.ts",
        callee_source: r#"
            export function tsLeaf(): number {
                return 7;
            }
        "#,
        callee_declaration: "function tsLeaf(): number",
        callee_name: "tsLeaf",
        caller_path: "ts/caller.ts",
        caller_source: r#"
            import { tsLeaf } from "./leaf";

            export function tsRoot(): number {
                return tsLeaf();
            }
        "#,
        caller_declaration: "function tsRoot(): number",
        caller_name: "tsRoot",
        call: "tsLeaf()",
    });
}

#[test]
fn typescript_tsx_direct_call_conformance() {
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::TypeScript,
        dialect: SemanticLanguage::TypeScriptTsx,
        callee_path: "tsx/leaf.tsx",
        callee_source: r#"
            export function tsxLeaf(): number {
                return 7;
            }
        "#,
        callee_declaration: "function tsxLeaf(): number",
        callee_name: "tsxLeaf",
        caller_path: "tsx/caller.tsx",
        caller_source: r#"
            import { tsxLeaf } from "./leaf";

            export function tsxRoot(): number {
                const value = tsxLeaf();
                const marker = <span>{value}</span>;
                return value;
            }
        "#,
        caller_declaration: "function tsxRoot(): number",
        caller_name: "tsxRoot",
        call: "tsxLeaf()",
    });
}

#[test]
fn javascript_direct_call_conformance() {
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::JavaScript,
        dialect: SemanticLanguage::Standard(Language::JavaScript),
        callee_path: "js/leaf.js",
        callee_source: r#"
            export function jsLeaf() {
                return 7;
            }
        "#,
        callee_declaration: "function jsLeaf()",
        callee_name: "jsLeaf",
        caller_path: "js/caller.js",
        caller_source: r#"
            import { jsLeaf } from "./leaf.js";

            export function jsRoot() {
                return jsLeaf();
            }
        "#,
        caller_declaration: "function jsRoot()",
        caller_name: "jsRoot",
        call: "jsLeaf()",
    });
}

#[test]
fn javascript_jsx_direct_call_conformance() {
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::JavaScript,
        dialect: SemanticLanguage::Standard(Language::JavaScript),
        callee_path: "jsx/leaf.jsx",
        callee_source: r#"
            export function jsxLeaf() {
                return 7;
            }
        "#,
        callee_declaration: "function jsxLeaf()",
        callee_name: "jsxLeaf",
        caller_path: "jsx/caller.jsx",
        caller_source: r#"
            import { jsxLeaf } from "./leaf.jsx";

            export function jsxRoot() {
                const value = jsxLeaf();
                return <View value={value} />;
            }
        "#,
        caller_declaration: "function jsxRoot()",
        caller_name: "jsxRoot",
        call: "jsxLeaf()",
    });
}

#[test]
fn javascript_scoped_gaps_and_class_field_arrow_name_are_source_backed() {
    let project = InlineTestProject::with_language(Language::JavaScript)
        .file(
            "src/features.js",
            r#"
                function acquire() {
                    return {};
                }

                function resources() {
                    using resource = acquire();
                }

                function resourceItems() {
                    return [];
                }

                function useEach() {
                    for (using resource of resourceItems()) {
                        consume(resource);
                    }
                }

                async function useEachAsync() {
                    for await (using resource of resourceItems()) {
                        consume(resource);
                    }
                }

                function* values() {
                    yield 1;
                }

                function view(value) {
                    return <View value={value} />;
                }

                class Worker {
                    run = () => {
                        return 1;
                    };
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/features.js");
    graph
        .bind(
            "using_gap",
            PointSelector::new("using resource = acquire();")
                .procedure("resources")
                .effect("gap"),
        )
        .bind(
            "acquire_continuation",
            PointSelector::new("acquire()")
                .procedure("resources")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "for_using_items_continuation",
            PointSelector::new("resourceItems()")
                .procedure("useEach")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "for_using_gap",
            PointSelector::new("for (using resource of resourceItems())")
                .procedure("useEach")
                .effect("gap")
                .anchor_occurrence(1),
        )
        .bind(
            "for_await_using_items_continuation",
            PointSelector::new("resourceItems()")
                .procedure("useEachAsync")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "for_await_using_gap",
            PointSelector::new("for await (using resource of resourceItems())")
                .procedure("useEachAsync")
                .effect("gap")
                .anchor_occurrence(1),
        )
        .bind(
            "yield_gap",
            PointSelector::new("yield 1")
                .procedure("values")
                .effect("gap"),
        )
        .bind(
            "jsx_gap",
            PointSelector::new("<View value={value} />")
                .procedure("view")
                .effect("gap"),
        )
        .bind(
            "field_arrow_entry",
            PointSelector::new("() =>").procedure("run").effect("entry"),
        );

    graph.assert_point_gap(
        "using_gap",
        SemanticCapability::ResourceManagement,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors(
        "acquire_continuation",
        &[cfg_edge("using_gap", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "for_using_gap",
        SemanticCapability::ResourceManagement,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors(
        "for_using_items_continuation",
        &[cfg_edge("for_using_gap", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "for_await_using_gap",
        SemanticCapability::ResourceManagement,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "for_await_using_gap",
        SemanticCapability::AsyncSuspendResume,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors(
        "for_await_using_items_continuation",
        &[cfg_edge("for_await_using_gap", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "yield_gap",
        SemanticCapability::GeneratorSuspension,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "jsx_gap",
        SemanticCapability::Calls,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors("using_gap", &[]);
    graph.assert_successors("for_using_gap", &[]);
    graph.assert_successors("for_await_using_gap", &[]);
    graph.assert_successors("yield_gap", &[]);
    graph.assert_adjacency_symmetric();

    let generator = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure.properties().is_generator
                && procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("values")
        })
        .expect("JavaScript generator procedure should exist");
    assert_eq!(
        generator.properties().invocation,
        ProcedureInvocationKind::Deferred
    );

    let field_arrow = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure.kind() == ProcedureKind::Lambda
                && procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("run")
        })
        .expect("class field arrow should retain its field name");
    assert!(
        field_arrow
            .locator()
            .declaration()
            .segments()
            .iter()
            .any(|segment| {
                segment.kind() == DeclarationSegmentKind::Type && segment.name() == Some("Worker")
            })
    );
}

#[test]
fn csharp_branches_loops_and_nested_callables_are_separate() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "csharp/Flow.cs",
            r#"
                namespace Conformance
                {
                    public static class Flow
                    {
                        public static int Choose(bool flag, int count)
                        {
                            if (flag)
                                Positive();
                            else
                                Negative();

                            while (count > 0)
                                Tick();

                            Done();
                            return count;
                        }

                        public static void Nested()
                        {
                            void Local()
                            {
                                LocalBody();
                            }

                            System.Action callback = () => LambdaBody();
                            OuterBody();
                        }
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "csharp/Flow.cs");
    graph
        .bind(
            "choose_entry",
            PointSelector::new("public static int Choose")
                .procedure("Choose")
                .effect("entry"),
        )
        .bind(
            "branch",
            PointSelector::new("flag")
                .occurrence(1)
                .procedure("Choose")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "positive_statement",
            PointSelector::new("Positive();").procedure("Choose"),
        )
        .bind(
            "negative_statement",
            PointSelector::new("Negative();").procedure("Choose"),
        )
        .bind(
            "loop_test",
            PointSelector::new("count > 0")
                .procedure("Choose")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "loop_evaluation_entry",
            PointSelector::new("while (count > 0)")
                .procedure("Choose")
                .effect("gap")
                .anchor_occurrence(0),
        )
        .bind(
            "tick_statement",
            PointSelector::new("Tick();").procedure("Choose"),
        )
        .bind(
            "tick_normal",
            PointSelector::new("Tick()")
                .procedure("Choose")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "done_statement",
            PointSelector::new("Done();").procedure("Choose"),
        )
        .bind(
            "choose_return",
            PointSelector::new("return count;")
                .procedure("Choose")
                .effect("procedure_return"),
        )
        .bind(
            "nested_entry",
            PointSelector::new("public static void Nested")
                .procedure("Nested")
                .effect("entry"),
        )
        .bind(
            "outer_body",
            PointSelector::new("OuterBody()")
                .procedure("Nested")
                .effect("invoke"),
        )
        .bind(
            "local_entry",
            PointSelector::new("void Local()")
                .procedure("Local")
                .effect("entry"),
        )
        .bind(
            "local_body",
            PointSelector::new("LocalBody()")
                .procedure("Local")
                .effect("invoke"),
        )
        .bind(
            "lambda_entry",
            PointSelector::new("() => LambdaBody()")
                .procedure("callback")
                .effect("entry"),
        )
        .bind(
            "lambda_body",
            PointSelector::new("LambdaBody()")
                .procedure("callback")
                .effect("invoke"),
        );

    graph.assert_successors(
        "branch",
        &[
            cfg_edge("positive_statement", ControlEdgeKind::ConditionalTrue),
            cfg_edge("negative_statement", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_predecessors(
        "positive_statement",
        &[cfg_edge("branch", ControlEdgeKind::ConditionalTrue)],
    );
    graph.assert_predecessors(
        "negative_statement",
        &[cfg_edge("branch", ControlEdgeKind::ConditionalFalse)],
    );
    graph.assert_successors(
        "loop_test",
        &[
            cfg_edge("tick_statement", ControlEdgeKind::ConditionalTrue),
            cfg_edge("done_statement", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_predecessors(
        "tick_statement",
        &[cfg_edge("loop_test", ControlEdgeKind::ConditionalTrue)],
    );
    graph.assert_predecessors(
        "done_statement",
        &[cfg_edge("loop_test", ControlEdgeKind::ConditionalFalse)],
    );
    graph.assert_successors(
        "tick_normal",
        &[cfg_edge("loop_evaluation_entry", ControlEdgeKind::LoopBack)],
    );
    graph.assert_reachable("loop_evaluation_entry", "loop_test");
    graph.assert_reachable("choose_entry", "choose_return");
    graph.assert_unreachable("positive_statement", "negative_statement");
    graph.assert_unreachable("negative_statement", "positive_statement");

    graph.assert_reachable("nested_entry", "outer_body");
    graph.assert_reachable("local_entry", "local_body");
    graph.assert_reachable("lambda_entry", "lambda_body");
    for (procedure, body) in [("Nested", "LocalBody()"), ("Nested", "LambdaBody()")] {
        let error = graph
            .try_bind(
                "wrong_callable_scope",
                PointSelector::new(body)
                    .procedure(procedure)
                    .effect("invoke"),
            )
            .expect_err("nested callable bodies must not be points in the outer method");
        assert!(error.to_string().contains("matched no semantic"));
    }

    let procedures = graph.artifact().procedures();
    for (name, kind) in [
        ("Local", ProcedureKind::LocalFunction),
        ("callback", ProcedureKind::Lambda),
    ] {
        let procedure = procedures
            .iter()
            .find(|procedure| {
                procedure.kind() == kind
                    && procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
            })
            .unwrap_or_else(|| panic!("missing C# {kind:?} procedure {name}"));
        let parent = graph
            .artifact()
            .procedure(
                procedure
                    .lexical_parent()
                    .expect("nested C# callable should retain its lexical parent"),
            )
            .expect("nested C# callable parent should exist");
        assert_eq!(
            parent
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name()),
            Some("Nested")
        );
    }

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn csharp_yield_and_goto_stop_at_typed_boundaries() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "csharp/Boundaries.cs",
            r#"
                namespace Conformance
                {
                    public static class Boundaries
                    {
                        public static System.Collections.Generic.IEnumerable<int> Values()
                        {
                            yield return Produce();
                            AfterYield();
                        }

                        public static void Jump()
                        {
                            goto Done;
                            Never();
                        Done:
                            AfterGoto();
                        }
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "csharp/Boundaries.cs");
    graph
        .bind(
            "values_entry",
            PointSelector::new("IEnumerable<int> Values")
                .procedure("Values")
                .effect("entry"),
        )
        .bind(
            "produce_normal",
            PointSelector::new("Produce()")
                .procedure("Values")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "yield_gap",
            PointSelector::new("yield return Produce();")
                .procedure("Values")
                .effect("gap"),
        )
        .bind(
            "after_yield",
            PointSelector::new("AfterYield()")
                .procedure("Values")
                .effect("invoke"),
        )
        .bind(
            "jump_entry",
            PointSelector::new("public static void Jump")
                .procedure("Jump")
                .effect("entry"),
        )
        .bind(
            "goto_gap",
            PointSelector::new("goto Done;")
                .procedure("Jump")
                .effect("gap"),
        )
        .bind(
            "never",
            PointSelector::new("Never()")
                .procedure("Jump")
                .effect("invoke"),
        )
        .bind(
            "label_gap",
            PointSelector::new("Done:").procedure("Jump").effect("gap"),
        )
        .bind(
            "after_goto",
            PointSelector::new("AfterGoto()")
                .procedure("Jump")
                .effect("invoke"),
        );

    graph.assert_point_gap(
        "yield_gap",
        SemanticCapability::GeneratorSuspension,
        SemanticGapKind::Unsupported,
    );
    graph.assert_predecessors(
        "yield_gap",
        &[cfg_edge("produce_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors("yield_gap", &[]);
    graph.assert_reachable("values_entry", "yield_gap");
    graph.assert_unreachable("yield_gap", "after_yield");

    graph.assert_point_gap(
        "goto_gap",
        SemanticCapability::NonLocalControl,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "label_gap",
        SemanticCapability::NonLocalControl,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors("goto_gap", &[]);
    graph.assert_reachable("jump_entry", "goto_gap");
    graph.assert_unreachable("jump_entry", "never");
    graph.assert_unreachable("jump_entry", "label_gap");
    graph.assert_unreachable("goto_gap", "after_goto");
    graph.assert_reachable("label_gap", "after_goto");

    let values = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some("Values")
        })
        .expect("C# generator procedure should exist");
    assert!(values.properties().is_generator);
    assert_eq!(
        values.properties().invocation,
        ProcedureInvocationKind::Deferred
    );
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn csharp_await_has_explicit_normal_and_exceptional_resumes() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "csharp/AsyncFlow.cs",
            r#"
                namespace Conformance
                {
                    public static class AsyncFlow
                    {
                        public static async System.Threading.Tasks.Task<int> AwaitOne()
                        {
                            return await FetchAsync();
                        }
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "csharp/AsyncFlow.cs");
    graph
        .bind(
            "await_entry",
            PointSelector::new("Task<int> AwaitOne")
                .procedure("AwaitOne")
                .effect("entry"),
        )
        .bind(
            "fetch_invoke",
            PointSelector::new("FetchAsync()")
                .procedure("AwaitOne")
                .effect("invoke"),
        )
        .bind(
            "fetch_normal",
            PointSelector::new("FetchAsync()")
                .procedure("AwaitOne")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "fetch_exceptional",
            PointSelector::new("FetchAsync()")
                .procedure("AwaitOne")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "suspend",
            PointSelector::new("await FetchAsync()")
                .procedure("AwaitOne")
                .effect("async_suspend"),
        )
        .bind(
            "normal_resume",
            PointSelector::new("await FetchAsync()")
                .procedure("AwaitOne")
                .effect("async_resume")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "exceptional_resume",
            PointSelector::new("await FetchAsync()")
                .procedure("AwaitOne")
                .effect("async_resume")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "await_return",
            PointSelector::new("return await FetchAsync();")
                .procedure("AwaitOne")
                .effect("procedure_return"),
        )
        .bind(
            "await_normal_exit",
            PointSelector::new("Task<int> AwaitOne")
                .procedure("AwaitOne")
                .effect("normal_exit"),
        )
        .bind(
            "await_exceptional_exit",
            PointSelector::new("Task<int> AwaitOne")
                .procedure("AwaitOne")
                .effect("exceptional_exit"),
        );

    graph.assert_successors(
        "fetch_invoke",
        &[
            cfg_edge("fetch_normal", ControlEdgeKind::Normal),
            cfg_edge("fetch_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "fetch_normal",
        &[cfg_edge("suspend", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "suspend",
        &[cfg_edge("fetch_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "suspend",
        &[
            cfg_edge("normal_resume", ControlEdgeKind::AsyncNormal),
            cfg_edge("exceptional_resume", ControlEdgeKind::AsyncExceptional),
        ],
    );
    graph.assert_predecessors(
        "normal_resume",
        &[cfg_edge("suspend", ControlEdgeKind::AsyncNormal)],
    );
    graph.assert_predecessors(
        "exceptional_resume",
        &[cfg_edge("suspend", ControlEdgeKind::AsyncExceptional)],
    );
    graph.assert_successors(
        "normal_resume",
        &[cfg_edge("await_return", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "exceptional_resume",
        &[cfg_edge(
            "await_exceptional_exit",
            ControlEdgeKind::Exceptional,
        )],
    );
    graph.assert_successors(
        "fetch_exceptional",
        &[cfg_edge(
            "await_exceptional_exit",
            ControlEdgeKind::Exceptional,
        )],
    );
    graph.assert_successors(
        "await_return",
        &[cfg_edge("await_normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "await_normal_exit",
        &[cfg_edge("await_return", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("await_entry", "await_normal_exit");
    graph.assert_reachable("await_entry", "await_exceptional_exit");

    let await_one = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| {
            procedure
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name())
                == Some("AwaitOne")
        })
        .expect("C# async procedure should exist");
    assert!(await_one.properties().is_async);
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn csharp_cleanup_constructs_preserve_flow_and_report_scoped_gaps() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "csharp/CleanupFlow.cs",
            r#"
                namespace Conformance
                {
                    public static class CleanupFlow
                    {
                        public static void Managed()
                        {
                            using (var resource = Acquire())
                            {
                                lock (Gate())
                                {
                                    Use(resource);
                                }
                            }
                            AfterManaged();
                        }

                        public static void FinallyFlow()
                        {
                            try
                            {
                                Work();
                            }
                            finally
                            {
                                Cleanup();
                            }
                            AfterFinally();
                        }

                        public static void UsingDeclaration()
                        {
                            using var resource = AcquireDeclared();
                            AfterUsingDeclaration();
                        }
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "csharp/CleanupFlow.cs");
    graph
        .bind(
            "managed_entry",
            PointSelector::new("public static void Managed")
                .procedure("Managed")
                .effect("entry"),
        )
        .bind(
            "acquire_normal",
            PointSelector::new("Acquire()")
                .procedure("Managed")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "using_boundary",
            PointSelector::new("var resource = Acquire()")
                .procedure("Managed")
                .effect("gap")
                .anchor_occurrence(0),
        )
        .bind(
            "using_body_entry",
            PointSelector::new(
                "{\n                                lock (Gate())\n                                {\n                                    Use(resource);\n                                }\n                            }",
            )
                .procedure("Managed")
                .anchor_occurrence(0),
        )
        .bind(
            "gate_invoke",
            PointSelector::new("Gate()")
                .procedure("Managed")
                .effect("invoke"),
        )
        .bind(
            "gate_normal",
            PointSelector::new("Gate()")
                .procedure("Managed")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "lock_boundary",
            PointSelector::new("Gate()")
                .procedure("Managed")
                .effect("gap")
                .anchor_occurrence(0),
        )
        .bind(
            "lock_body_entry",
            PointSelector::new(
                "{\n                                    Use(resource);\n                                }",
            )
                .procedure("Managed")
                .anchor_occurrence(0),
        )
        .bind(
            "use_invoke",
            PointSelector::new("Use(resource)")
                .procedure("Managed")
                .effect("invoke"),
        )
        .bind(
            "after_managed",
            PointSelector::new("AfterManaged()")
                .procedure("Managed")
                .effect("invoke"),
        )
        .bind(
            "work_normal",
            PointSelector::new("Work()")
                .procedure("FinallyFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "try_body_exit",
            PointSelector::new(
                "{\n                                Work();\n                            }",
            )
            .procedure("FinallyFlow")
            .outgoing_kind(ControlEdgeKind::Cleanup),
        )
        .bind(
            "normal_cleanup_entry",
            PointSelector::new(
                "{\n                                Cleanup();\n                            }",
            )
            .procedure("FinallyFlow")
            .outgoing_kind(ControlEdgeKind::Normal)
            .anchor_occurrence(0),
        )
        .bind(
            "normal_cleanup_statement",
            PointSelector::new("Cleanup();")
                .procedure("FinallyFlow")
                .outgoing_kind(ControlEdgeKind::Normal)
                .anchor_occurrence(1),
        )
        .bind(
            "normal_cleanup_invoke",
            PointSelector::new("Cleanup()")
                .procedure("FinallyFlow")
                .effect("invoke")
                .anchor_occurrence(3),
        )
        .bind(
            "cleanup_normal",
            PointSelector::new("Cleanup()")
                .procedure("FinallyFlow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal)
                .anchor_occurrence(4),
        )
        .bind(
            "after_finally_statement",
            PointSelector::new("AfterFinally();")
                .procedure("FinallyFlow")
                .anchor_occurrence(0),
        )
        .bind(
            "after_finally",
            PointSelector::new("AfterFinally()")
                .procedure("FinallyFlow")
                .effect("invoke"),
        )
        .bind(
            "using_declaration_gap",
            PointSelector::new("using var resource = AcquireDeclared();")
                .procedure("UsingDeclaration")
                .effect("gap")
                .anchor_occurrence(0),
        )
        .bind(
            "declared_expression",
            PointSelector::new("AcquireDeclared()")
                .procedure("UsingDeclaration")
                .anchor_occurrence(0),
        )
        .bind(
            "declared_acquire",
            PointSelector::new("AcquireDeclared()")
                .procedure("UsingDeclaration")
                .effect("invoke"),
        )
        .bind(
            "declared_normal",
            PointSelector::new("AcquireDeclared()")
                .procedure("UsingDeclaration")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "after_using_declaration_statement",
            PointSelector::new("AfterUsingDeclaration();")
                .procedure("UsingDeclaration")
                .anchor_occurrence(0),
        )
        .bind(
            "after_using_declaration",
            PointSelector::new("AfterUsingDeclaration()")
                .procedure("UsingDeclaration")
                .effect("invoke"),
        );

    graph.assert_successors(
        "acquire_normal",
        &[cfg_edge("using_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "using_boundary",
        &[cfg_edge("acquire_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "using_boundary",
        SemanticCapability::ResourceManagement,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "using_boundary",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors(
        "using_boundary",
        &[cfg_edge("using_body_entry", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("using_body_entry", "gate_invoke");
    graph.assert_successors(
        "gate_normal",
        &[cfg_edge("lock_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "lock_boundary",
        &[cfg_edge("gate_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "lock_boundary",
        SemanticCapability::CleanupControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "lock_boundary",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors(
        "lock_boundary",
        &[cfg_edge("lock_body_entry", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("lock_body_entry", "use_invoke");
    graph.assert_reachable("managed_entry", "after_managed");

    graph.assert_successors(
        "work_normal",
        &[cfg_edge("try_body_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "try_body_exit",
        &[cfg_edge("normal_cleanup_entry", ControlEdgeKind::Cleanup)],
    );
    graph.assert_predecessors(
        "normal_cleanup_entry",
        &[cfg_edge("try_body_exit", ControlEdgeKind::Cleanup)],
    );
    graph.assert_successors(
        "normal_cleanup_entry",
        &[cfg_edge(
            "normal_cleanup_statement",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_successors(
        "normal_cleanup_statement",
        &[cfg_edge("normal_cleanup_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "cleanup_normal",
        &[cfg_edge("after_finally_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "after_finally_statement",
        &[cfg_edge("after_finally", ControlEdgeKind::Normal)],
    );

    graph.assert_point_gap(
        "using_declaration_gap",
        SemanticCapability::ResourceManagement,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "using_declaration_gap",
        SemanticCapability::CleanupControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors(
        "using_declaration_gap",
        &[cfg_edge("declared_expression", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("declared_expression", "declared_acquire");
    graph.assert_successors(
        "declared_normal",
        &[cfg_edge(
            "after_using_declaration_statement",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_predecessors(
        "after_using_declaration_statement",
        &[cfg_edge("declared_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "after_using_declaration_statement",
        &[cfg_edge("after_using_declaration", ControlEdgeKind::Normal)],
    );

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn csharp_indexed_access_preserves_nested_call_sites() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "csharp/IndexedCalls.cs",
            r#"
                namespace Conformance
                {
                    public static class IndexedCalls
                    {
                        public static void InvokeIndexed()
                        {
                            handlers[NextIndex()]();
                            AfterIndexedInvocation();
                        }

                        public static void ConditionalIndex()
                        {
                            var value = items?[NextIndex()];
                            AfterConditionalIndex();
                        }
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "csharp/IndexedCalls.cs");
    graph
        .bind(
            "indexed_entry",
            PointSelector::new("public static void InvokeIndexed")
                .procedure("InvokeIndexed")
                .effect("entry"),
        )
        .bind(
            "indexed_access_gap",
            PointSelector::new("handlers[NextIndex()]")
                .procedure("InvokeIndexed")
                .effect("gap"),
        )
        .bind(
            "handlers_value",
            PointSelector::new("handlers")
                .procedure("InvokeIndexed")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "indexed_binding",
            PointSelector::new("[NextIndex()]")
                .procedure("InvokeIndexed")
                .anchor_occurrence(0),
        )
        .bind(
            "indexed_next_expression",
            PointSelector::new("NextIndex()")
                .procedure("InvokeIndexed")
                .anchor_occurrence(0),
        )
        .bind(
            "indexed_next_invoke",
            PointSelector::new("NextIndex()")
                .procedure("InvokeIndexed")
                .effect("invoke"),
        )
        .bind(
            "indexed_next_normal",
            PointSelector::new("NextIndex()")
                .procedure("InvokeIndexed")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "indexed_next_exceptional",
            PointSelector::new("NextIndex()")
                .procedure("InvokeIndexed")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "indexed_outer_invoke",
            PointSelector::new("handlers[NextIndex()]()")
                .procedure("InvokeIndexed")
                .effect("invoke"),
        )
        .bind(
            "indexed_outer_normal",
            PointSelector::new("handlers[NextIndex()]()")
                .procedure("InvokeIndexed")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "indexed_outer_exceptional",
            PointSelector::new("handlers[NextIndex()]()")
                .procedure("InvokeIndexed")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "after_indexed_statement",
            PointSelector::new("AfterIndexedInvocation();").procedure("InvokeIndexed"),
        )
        .bind(
            "after_indexed_invoke",
            PointSelector::new("AfterIndexedInvocation()")
                .procedure("InvokeIndexed")
                .effect("invoke"),
        )
        .bind(
            "conditional_entry",
            PointSelector::new("public static void ConditionalIndex")
                .procedure("ConditionalIndex")
                .effect("entry"),
        )
        .bind(
            "conditional_boundary",
            PointSelector::new("items?[NextIndex()]")
                .procedure("ConditionalIndex")
                .effect("gap"),
        )
        .bind(
            "conditional_split",
            PointSelector::new("items")
                .procedure("ConditionalIndex")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "conditional_binding",
            PointSelector::new("[NextIndex()]")
                .procedure("ConditionalIndex")
                .effect("gap"),
        )
        .bind(
            "conditional_next_expression",
            PointSelector::new("NextIndex()")
                .procedure("ConditionalIndex")
                .anchor_occurrence(0),
        )
        .bind(
            "conditional_next_invoke",
            PointSelector::new("NextIndex()")
                .procedure("ConditionalIndex")
                .effect("invoke"),
        )
        .bind(
            "conditional_next_normal",
            PointSelector::new("NextIndex()")
                .procedure("ConditionalIndex")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "conditional_next_exceptional",
            PointSelector::new("NextIndex()")
                .procedure("ConditionalIndex")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "after_conditional_statement",
            PointSelector::new("AfterConditionalIndex();").procedure("ConditionalIndex"),
        )
        .bind(
            "after_conditional_invoke",
            PointSelector::new("AfterConditionalIndex()")
                .procedure("ConditionalIndex")
                .effect("invoke"),
        );

    graph.assert_point_gap(
        "indexed_access_gap",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors(
        "indexed_access_gap",
        &[cfg_edge("handlers_value", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "handlers_value",
        &[cfg_edge("indexed_binding", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "indexed_binding",
        &[cfg_edge("indexed_next_expression", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("indexed_next_expression", "indexed_next_invoke");
    graph.assert_successors(
        "indexed_next_invoke",
        &[
            cfg_edge("indexed_next_normal", ControlEdgeKind::Normal),
            cfg_edge("indexed_next_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "indexed_next_normal",
        &[cfg_edge("indexed_outer_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "indexed_outer_invoke",
        &[cfg_edge("indexed_next_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "indexed_outer_invoke",
        &[
            cfg_edge("indexed_outer_normal", ControlEdgeKind::Normal),
            cfg_edge("indexed_outer_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "indexed_outer_normal",
        &[cfg_edge("after_indexed_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "after_indexed_statement",
        &[cfg_edge("after_indexed_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("indexed_entry", "after_indexed_invoke");
    graph.assert_unreachable("indexed_outer_invoke", "indexed_next_invoke");

    graph.assert_point_gap(
        "conditional_boundary",
        SemanticCapability::NormalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "conditional_binding",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors(
        "conditional_boundary",
        &[cfg_edge("conditional_split", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "conditional_split",
        &[
            cfg_edge("conditional_binding", ControlEdgeKind::ConditionalTrue),
            cfg_edge(
                "after_conditional_statement",
                ControlEdgeKind::ConditionalFalse,
            ),
        ],
    );
    graph.assert_successors(
        "conditional_binding",
        &[cfg_edge(
            "conditional_next_expression",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_reachable("conditional_next_expression", "conditional_next_invoke");
    graph.assert_successors(
        "conditional_next_invoke",
        &[
            cfg_edge("conditional_next_normal", ControlEdgeKind::Normal),
            cfg_edge("conditional_next_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "conditional_next_normal",
        &[cfg_edge(
            "after_conditional_statement",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_predecessors(
        "after_conditional_statement",
        &[
            cfg_edge("conditional_split", ControlEdgeKind::ConditionalFalse),
            cfg_edge("conditional_next_normal", ControlEdgeKind::Normal),
        ],
    );
    graph.assert_successors(
        "after_conditional_statement",
        &[cfg_edge(
            "after_conditional_invoke",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_reachable("conditional_entry", "conditional_next_invoke");
    graph.assert_reachable("conditional_entry", "after_conditional_invoke");
    graph.assert_unreachable("after_conditional_invoke", "conditional_next_invoke");

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn csharp_target_typed_new_evaluates_arguments_then_initializer() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "csharp/TargetTypedNew.cs",
            r#"
                namespace Conformance
                {
                    public static class TargetTypedNew
                    {
                        public static Widget Build()
                        {
                            Widget widget = new(F()) { P = G() };
                            AfterConstruction(widget);
                            return widget;
                        }
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "csharp/TargetTypedNew.cs");
    graph
        .bind(
            "build_entry",
            PointSelector::new("public static Widget Build")
                .procedure("Build")
                .effect("entry"),
        )
        .bind(
            "factory_invoke",
            PointSelector::new("F()")
                .procedure("Build")
                .effect("invoke"),
        )
        .bind(
            "factory_normal",
            PointSelector::new("F()")
                .procedure("Build")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "factory_exceptional",
            PointSelector::new("F()")
                .procedure("Build")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "constructor_invoke",
            PointSelector::new("new(F()) { P = G() }")
                .procedure("Build")
                .effect("invoke"),
        )
        .bind(
            "constructor_normal",
            PointSelector::new("new(F()) { P = G() }")
                .procedure("Build")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "constructor_exceptional",
            PointSelector::new("new(F()) { P = G() }")
                .procedure("Build")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "initializer_assignment",
            PointSelector::new("P = G()")
                .procedure("Build")
                .effect("gap"),
        )
        .bind(
            "initializer_property",
            PointSelector::new("P")
                .procedure("Build")
                .anchor_occurrence(0),
        )
        .bind(
            "initializer_call_expression",
            PointSelector::new("G()")
                .procedure("Build")
                .anchor_occurrence(0),
        )
        .bind(
            "initializer_invoke",
            PointSelector::new("G()")
                .procedure("Build")
                .effect("invoke"),
        )
        .bind(
            "initializer_normal",
            PointSelector::new("G()")
                .procedure("Build")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "initializer_exceptional",
            PointSelector::new("G()")
                .procedure("Build")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "after_construction_statement",
            PointSelector::new("AfterConstruction(widget);").procedure("Build"),
        )
        .bind(
            "after_construction_invoke",
            PointSelector::new("AfterConstruction(widget)")
                .procedure("Build")
                .effect("invoke"),
        )
        .bind(
            "build_return",
            PointSelector::new("return widget;")
                .procedure("Build")
                .effect("procedure_return"),
        );

    graph.assert_successors(
        "factory_invoke",
        &[
            cfg_edge("factory_normal", ControlEdgeKind::Normal),
            cfg_edge("factory_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "factory_normal",
        &[cfg_edge("constructor_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "constructor_invoke",
        &[cfg_edge("factory_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "constructor_invoke",
        &[
            cfg_edge("constructor_normal", ControlEdgeKind::Normal),
            cfg_edge("constructor_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "constructor_normal",
        &[cfg_edge("initializer_assignment", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "initializer_assignment",
        &[cfg_edge("constructor_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "initializer_assignment",
        &[cfg_edge("initializer_property", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "initializer_property",
        &[cfg_edge(
            "initializer_call_expression",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_successors(
        "initializer_call_expression",
        &[cfg_edge("initializer_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "initializer_invoke",
        &[
            cfg_edge("initializer_normal", ControlEdgeKind::Normal),
            cfg_edge("initializer_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "initializer_normal",
        &[cfg_edge(
            "after_construction_statement",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_predecessors(
        "after_construction_statement",
        &[cfg_edge("initializer_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("after_construction_statement", "after_construction_invoke");
    graph.assert_reachable("after_construction_invoke", "build_return");
    graph.assert_reachable("build_entry", "build_return");
    graph.assert_unreachable("constructor_invoke", "factory_invoke");
    graph.assert_unreachable("after_construction_invoke", "initializer_invoke");

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn csharp_method_preprocessor_condition_is_a_terminal_typed_boundary() {
    let project = InlineTestProject::with_language(Language::CSharp)
        .file(
            "csharp/Configured.cs",
            r#"
                namespace Conformance
                {
                    public static class Configured
                    {
                        public static void Run()
                        {
                            BeforeConfiguration();
#if FIRST
                            FirstBranch();
#elif SECOND
                            SecondBranch();
#else
                            FallbackBranch();
#endif
                            AfterConfiguration();
                        }
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "csharp/Configured.cs");
    graph
        .bind(
            "configured_entry",
            PointSelector::new("public static void Run")
                .procedure("Run")
                .effect("entry"),
        )
        .bind(
            "before_configuration_invoke",
            PointSelector::new("BeforeConfiguration()")
                .procedure("Run")
                .effect("invoke"),
        )
        .bind(
            "before_configuration_normal",
            PointSelector::new("BeforeConfiguration()")
                .procedure("Run")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "before_configuration_exceptional",
            PointSelector::new("BeforeConfiguration()")
                .procedure("Run")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "configuration_boundary",
            PointSelector::new("#if FIRST")
                .procedure("Run")
                .effect("gap"),
        )
        .bind(
            "after_configuration_statement",
            PointSelector::new("AfterConfiguration();").procedure("Run"),
        )
        .bind(
            "after_configuration_invoke",
            PointSelector::new("AfterConfiguration()")
                .procedure("Run")
                .effect("invoke"),
        );

    graph.assert_successors(
        "before_configuration_invoke",
        &[
            cfg_edge("before_configuration_normal", ControlEdgeKind::Normal),
            cfg_edge(
                "before_configuration_exceptional",
                ControlEdgeKind::Exceptional,
            ),
        ],
    );
    graph.assert_successors(
        "before_configuration_normal",
        &[cfg_edge("configuration_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "configuration_boundary",
        &[cfg_edge(
            "before_configuration_normal",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_point_gap(
        "configuration_boundary",
        SemanticCapability::NormalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors("configuration_boundary", &[]);
    graph.assert_reachable("configured_entry", "configuration_boundary");
    graph.assert_unreachable("configured_entry", "after_configuration_statement");
    graph.assert_unreachable("configuration_boundary", "after_configuration_statement");
    graph.assert_successors(
        "after_configuration_statement",
        &[cfg_edge(
            "after_configuration_invoke",
            ControlEdgeKind::Normal,
        )],
    );

    for branch_call in ["FirstBranch()", "SecondBranch()", "FallbackBranch()"] {
        let error = graph
            .try_bind(
                format!("unscheduled_{branch_call}"),
                PointSelector::new(branch_call)
                    .procedure("Run")
                    .effect("invoke"),
            )
            .expect_err("preprocessor branch statements must not be guessed without configuration");
        assert!(error.to_string().contains("matched no semantic"));
    }

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn python_loop_else_routes_break_and_exhaustion_separately() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "python/loop_paths.py",
            r#"def loop_paths(values, stop):
    for value in values:
        if value < 0:
            continue
        if value == stop:
            break
        consume(value)
    else:
        exhausted()
    after_loop()
    return value
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "python/loop_paths.py");
    graph
        .bind(
            "loop_paths_entry",
            PointSelector::new("def loop_paths(values, stop):")
                .procedure("loop_paths")
                .effect("entry"),
        )
        .bind(
            "loop_dispatch",
            PointSelector::new("for value in values:")
                .procedure("loop_paths")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "iteration_binding",
            PointSelector::new("value")
                .occurrence(1)
                .procedure("loop_paths")
                .anchor_occurrence(0),
        )
        .bind(
            "continue_transfer",
            PointSelector::new("continue")
                .procedure("loop_paths")
                .anchor_occurrence(1)
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "break_transfer",
            PointSelector::new("break")
                .procedure("loop_paths")
                .anchor_occurrence(1)
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "consume_normal",
            PointSelector::new("consume(value)")
                .procedure("loop_paths")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "exhausted_statement",
            PointSelector::new("exhausted()")
                .procedure("loop_paths")
                .anchor_occurrence(0),
        )
        .bind(
            "exhausted_invoke",
            PointSelector::new("exhausted()")
                .procedure("loop_paths")
                .effect("invoke"),
        )
        .bind(
            "exhausted_normal",
            PointSelector::new("exhausted()")
                .procedure("loop_paths")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "after_loop_statement",
            PointSelector::new("after_loop()")
                .procedure("loop_paths")
                .anchor_occurrence(0),
        )
        .bind(
            "after_loop_invoke",
            PointSelector::new("after_loop()")
                .procedure("loop_paths")
                .effect("invoke"),
        )
        .bind(
            "loop_return",
            PointSelector::new("return value")
                .procedure("loop_paths")
                .effect("procedure_return"),
        );

    graph.assert_point_gap(
        "loop_dispatch",
        SemanticCapability::Calls,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "loop_dispatch",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors(
        "loop_dispatch",
        &[
            cfg_edge("iteration_binding", ControlEdgeKind::ConditionalTrue),
            cfg_edge("exhausted_statement", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_predecessors(
        "exhausted_statement",
        &[cfg_edge("loop_dispatch", ControlEdgeKind::ConditionalFalse)],
    );
    graph.assert_successors(
        "continue_transfer",
        &[cfg_edge("loop_dispatch", ControlEdgeKind::LoopBack)],
    );
    graph.assert_successors(
        "consume_normal",
        &[cfg_edge("loop_dispatch", ControlEdgeKind::LoopBack)],
    );
    graph.assert_reachable("exhausted_statement", "exhausted_invoke");
    graph.assert_successors(
        "exhausted_normal",
        &[cfg_edge("after_loop_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "break_transfer",
        &[cfg_edge("after_loop_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "after_loop_statement",
        &[
            cfg_edge("break_transfer", ControlEdgeKind::Normal),
            cfg_edge("exhausted_normal", ControlEdgeKind::Normal),
        ],
    );
    graph.assert_reachable("after_loop_statement", "after_loop_invoke");
    graph.assert_reachable("loop_paths_entry", "loop_return");
    graph.assert_unreachable("break_transfer", "exhausted_invoke");
    graph.assert_unreachable("exhausted_invoke", "break_transfer");

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn python_try_else_finally_and_nested_calls_preserve_order() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "python/control.py",
            r#"def guarded(flag):
    try:
        work()
        if flag:
            raise ValueError()
    except ValueError:
        handled()
    else:
        clean_path()
    finally:
        cleanup()
    after_try()

def evaluate():
    result = combine(first(), second(inner()))
    after_calls(result)
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "python/control.py");
    graph
        .bind(
            "guarded_entry",
            PointSelector::new("def guarded(flag):")
                .procedure("guarded")
                .effect("entry"),
        )
        .bind(
            "work_invoke",
            PointSelector::new("work()")
                .procedure("guarded")
                .effect("invoke"),
        )
        .bind(
            "work_normal",
            PointSelector::new("work()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "work_exceptional",
            PointSelector::new("work()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "if_statement",
            PointSelector::new("if flag:\n            raise ValueError()")
                .procedure("guarded")
                .anchor_occurrence(0),
        )
        .bind(
            "handler_dispatch",
            PointSelector::new("try:")
                .procedure("guarded")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "handler_clause",
            PointSelector::new("except ValueError:\n        handled()")
                .procedure("guarded")
                .anchor_occurrence(0),
        )
        .bind(
            "unmatched_exception",
            PointSelector::new("try:")
                .procedure("guarded")
                .anchor_occurrence(2)
                .outgoing_kind(ControlEdgeKind::Cleanup),
        )
        .bind(
            "handled_invoke",
            PointSelector::new("handled()")
                .procedure("guarded")
                .effect("invoke"),
        )
        .bind(
            "handled_normal",
            PointSelector::new("handled()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "clean_path_invoke",
            PointSelector::new("clean_path()")
                .procedure("guarded")
                .effect("invoke"),
        )
        .bind(
            "clean_path_normal",
            PointSelector::new("clean_path()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "clean_path_exceptional",
            PointSelector::new("clean_path()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Cleanup),
        )
        .bind(
            "common_cleanup_invoke",
            PointSelector::new("cleanup()")
                .procedure("guarded")
                .effect("invoke")
                .anchor_occurrence(8),
        )
        .bind(
            "common_cleanup_normal",
            PointSelector::new("cleanup()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal)
                .anchor_occurrence(9),
        )
        .bind(
            "after_try_statement",
            PointSelector::new("after_try()")
                .procedure("guarded")
                .anchor_occurrence(0),
        )
        .bind(
            "after_try_invoke",
            PointSelector::new("after_try()")
                .procedure("guarded")
                .effect("invoke"),
        )
        .bind(
            "guarded_exceptional_exit",
            PointSelector::new("def guarded(flag):")
                .procedure("guarded")
                .effect("exceptional_exit"),
        )
        .bind(
            "evaluate_entry",
            PointSelector::new("def evaluate():")
                .procedure("evaluate")
                .effect("entry"),
        )
        .bind(
            "first_invoke",
            PointSelector::new("first()")
                .procedure("evaluate")
                .effect("invoke"),
        )
        .bind(
            "first_normal",
            PointSelector::new("first()")
                .procedure("evaluate")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "first_exceptional",
            PointSelector::new("first()")
                .procedure("evaluate")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "second_expression",
            PointSelector::new("second(inner())")
                .procedure("evaluate")
                .anchor_occurrence(0),
        )
        .bind(
            "inner_expression",
            PointSelector::new("inner()")
                .procedure("evaluate")
                .anchor_occurrence(0),
        )
        .bind(
            "inner_invoke",
            PointSelector::new("inner()")
                .procedure("evaluate")
                .effect("invoke"),
        )
        .bind(
            "inner_normal",
            PointSelector::new("inner()")
                .procedure("evaluate")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "inner_exceptional",
            PointSelector::new("inner()")
                .procedure("evaluate")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "second_invoke",
            PointSelector::new("second(inner())")
                .procedure("evaluate")
                .effect("invoke"),
        )
        .bind(
            "second_normal",
            PointSelector::new("second(inner())")
                .procedure("evaluate")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "second_exceptional",
            PointSelector::new("second(inner())")
                .procedure("evaluate")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "combine_invoke",
            PointSelector::new("combine(first(), second(inner()))")
                .procedure("evaluate")
                .effect("invoke"),
        )
        .bind(
            "combine_normal",
            PointSelector::new("combine(first(), second(inner()))")
                .procedure("evaluate")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "combine_exceptional",
            PointSelector::new("combine(first(), second(inner()))")
                .procedure("evaluate")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "after_calls_statement",
            PointSelector::new("after_calls(result)")
                .procedure("evaluate")
                .anchor_occurrence(0),
        )
        .bind(
            "after_calls_invoke",
            PointSelector::new("after_calls(result)")
                .procedure("evaluate")
                .effect("invoke"),
        );

    graph.assert_successors(
        "work_invoke",
        &[
            cfg_edge("work_normal", ControlEdgeKind::Normal),
            cfg_edge("work_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "work_normal",
        &[cfg_edge("if_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "work_exceptional",
        &[cfg_edge("handler_dispatch", ControlEdgeKind::Exceptional)],
    );
    graph.assert_point_gap(
        "handler_dispatch",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_successors(
        "handler_dispatch",
        &[
            cfg_edge("handler_clause", ControlEdgeKind::SwitchCase),
            cfg_edge("unmatched_exception", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_reachable("handler_clause", "handled_invoke");
    graph.assert_reachable("handled_normal", "common_cleanup_invoke");
    graph.assert_reachable("work_normal", "clean_path_invoke");
    graph.assert_reachable("clean_path_normal", "common_cleanup_invoke");
    graph.assert_unreachable("clean_path_exceptional", "handler_clause");
    graph.assert_reachable("clean_path_exceptional", "guarded_exceptional_exit");
    graph.assert_reachable("unmatched_exception", "guarded_exceptional_exit");
    graph.assert_successors(
        "common_cleanup_normal",
        &[cfg_edge("after_try_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "after_try_statement",
        &[cfg_edge("common_cleanup_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("after_try_statement", "after_try_invoke");
    graph.assert_reachable("guarded_entry", "after_try_invoke");

    for (invoke, normal, exceptional) in [
        ("first_invoke", "first_normal", "first_exceptional"),
        ("inner_invoke", "inner_normal", "inner_exceptional"),
        ("second_invoke", "second_normal", "second_exceptional"),
        ("combine_invoke", "combine_normal", "combine_exceptional"),
    ] {
        graph.assert_successors(
            invoke,
            &[
                cfg_edge(normal, ControlEdgeKind::Normal),
                cfg_edge(exceptional, ControlEdgeKind::Exceptional),
            ],
        );
    }
    graph.assert_successors(
        "first_normal",
        &[cfg_edge("second_expression", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "second_expression",
        &[cfg_edge("inner_expression", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("inner_expression", "inner_invoke");
    graph.assert_successors(
        "inner_normal",
        &[cfg_edge("second_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "second_invoke",
        &[cfg_edge("inner_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "second_normal",
        &[cfg_edge("combine_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "combine_invoke",
        &[cfg_edge("second_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "combine_normal",
        &[cfg_edge("after_calls_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("after_calls_statement", "after_calls_invoke");
    graph.assert_reachable("evaluate_entry", "after_calls_invoke");
    graph.assert_unreachable("combine_invoke", "first_invoke");

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn python_nested_definitions_and_lambdas_are_separate() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "python/callables.py",
            r#"def outer():
    def local():
        local_body()

    callback = lambda: lambda_body()
    outer_body()
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "python/callables.py");
    graph
        .bind(
            "outer_entry",
            PointSelector::new("def outer():")
                .procedure("outer")
                .effect("entry"),
        )
        .bind(
            "outer_body",
            PointSelector::new("outer_body()")
                .procedure("outer")
                .effect("invoke"),
        )
        .bind(
            "outer_body_normal",
            PointSelector::new("outer_body()")
                .procedure("outer")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "outer_body_exceptional",
            PointSelector::new("outer_body()")
                .procedure("outer")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "local_entry",
            PointSelector::new("def local():")
                .procedure("local")
                .effect("entry"),
        )
        .bind(
            "local_body",
            PointSelector::new("local_body()")
                .procedure("local")
                .effect("invoke"),
        )
        .bind(
            "local_body_normal",
            PointSelector::new("local_body()")
                .procedure("local")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "local_body_exceptional",
            PointSelector::new("local_body()")
                .procedure("local")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "lambda_entry",
            PointSelector::new("lambda: lambda_body()")
                .procedure("callback")
                .effect("entry"),
        )
        .bind(
            "lambda_body",
            PointSelector::new("lambda_body()")
                .procedure("callback")
                .effect("invoke"),
        )
        .bind(
            "lambda_body_normal",
            PointSelector::new("lambda_body()")
                .procedure("callback")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "lambda_body_exceptional",
            PointSelector::new("lambda_body()")
                .procedure("callback")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        );

    for (invoke, normal, exceptional) in [
        ("outer_body", "outer_body_normal", "outer_body_exceptional"),
        ("local_body", "local_body_normal", "local_body_exceptional"),
        (
            "lambda_body",
            "lambda_body_normal",
            "lambda_body_exceptional",
        ),
    ] {
        graph.assert_successors(
            invoke,
            &[
                cfg_edge(normal, ControlEdgeKind::Normal),
                cfg_edge(exceptional, ControlEdgeKind::Exceptional),
            ],
        );
        graph.assert_predecessors(normal, &[cfg_edge(invoke, ControlEdgeKind::Normal)]);
        graph.assert_predecessors(
            exceptional,
            &[cfg_edge(invoke, ControlEdgeKind::Exceptional)],
        );
    }
    graph.assert_reachable("outer_entry", "outer_body");
    graph.assert_reachable("local_entry", "local_body");
    graph.assert_reachable("lambda_entry", "lambda_body");
    for body in ["local_body()", "lambda_body()"] {
        let error = graph
            .try_bind(
                format!("wrong_outer_scope_{body}"),
                PointSelector::new(body).procedure("outer").effect("invoke"),
            )
            .expect_err("nested Python callable bodies must stay outside the outer CFG");
        assert!(error.to_string().contains("matched no semantic"));
    }

    for (name, kind) in [
        ("local", ProcedureKind::LocalFunction),
        ("callback", ProcedureKind::Lambda),
    ] {
        let procedure = graph
            .artifact()
            .procedures()
            .iter()
            .find(|procedure| {
                procedure.kind() == kind
                    && procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
            })
            .unwrap_or_else(|| panic!("missing Python {kind:?} procedure {name}"));
        let parent = graph
            .artifact()
            .procedure(
                procedure
                    .lexical_parent()
                    .expect("nested Python callable should retain its lexical parent"),
            )
            .expect("nested Python callable parent should exist");
        assert_eq!(
            parent
                .locator()
                .declaration()
                .segments()
                .last()
                .and_then(|segment| segment.name()),
            Some("outer")
        );
    }

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn python_default_lambdas_remain_in_the_definition_scope() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "python/callable_defaults.py",
            r#"def outer():
    def configured(factory=lambda: leaf()):
        factory()
    after_definition()
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "python/callable_defaults.py");
    graph
        .bind(
            "outer_entry",
            PointSelector::new("def outer():")
                .procedure("outer")
                .effect("entry"),
        )
        .bind(
            "configured_definition",
            PointSelector::new("def configured(factory=lambda: leaf()):\n        factory()")
                .procedure("outer")
                .anchor_occurrence(0),
        )
        .bind(
            "after_definition_statement",
            PointSelector::new("after_definition()")
                .procedure("outer")
                .anchor_occurrence(0),
        )
        .bind(
            "after_definition_invoke",
            PointSelector::new("after_definition()")
                .procedure("outer")
                .effect("invoke"),
        );

    graph.assert_point_gap(
        "configured_definition",
        SemanticCapability::Calls,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "configured_definition",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors(
        "configured_definition",
        &[cfg_edge(
            "after_definition_statement",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_predecessors(
        "after_definition_statement",
        &[cfg_edge("configured_definition", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("outer_entry", "after_definition_invoke");

    let lambda = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| procedure.kind() == ProcedureKind::Lambda)
        .expect("missing Python default-value lambda");
    let parent = graph
        .artifact()
        .procedure(
            lambda
                .lexical_parent()
                .expect("default-value lambda should retain the definition scope"),
        )
        .expect("default-value lambda parent should exist");
    assert_eq!(
        parent
            .locator()
            .declaration()
            .segments()
            .last()
            .and_then(|segment| segment.name()),
        Some("outer")
    );
    let named_path = lambda
        .locator()
        .declaration()
        .segments()
        .iter()
        .filter_map(|segment| segment.name())
        .collect::<Vec<_>>();
    assert_eq!(named_path, vec!["callable_defaults.py", "outer"]);
    assert!(!named_path.contains(&"configured"));

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn python_generator_expression_evaluates_only_its_outer_iterable_eagerly() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "python/generator_argument.py",
            r#"def use_generator():
    consume(transform(item) for item in source() if keep(item))
    after_generator()

def use_eager():
    consume_eager([transform_eager(item) for item in source_eager() if keep_eager(item)])
    after_eager()
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "python/generator_argument.py");
    graph
        .bind(
            "entry",
            PointSelector::new("def use_generator():")
                .procedure("use_generator")
                .effect("entry"),
        )
        .bind(
            "source_invoke",
            PointSelector::new("source()")
                .procedure("use_generator")
                .effect("invoke"),
        )
        .bind(
            "source_normal",
            PointSelector::new("source()")
                .procedure("use_generator")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "source_exceptional",
            PointSelector::new("source()")
                .procedure("use_generator")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "generator_boundary",
            PointSelector::new("for item in")
                .procedure("use_generator")
                .effect("gap")
                .anchor_occurrence(1),
        )
        .bind(
            "consume_invoke",
            PointSelector::new("consume(transform(item) for item in source() if keep(item))")
                .procedure("use_generator")
                .effect("invoke"),
        )
        .bind(
            "consume_normal",
            PointSelector::new("consume(transform(item) for item in source() if keep(item))")
                .procedure("use_generator")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "consume_exceptional",
            PointSelector::new("consume(transform(item) for item in source() if keep(item))")
                .procedure("use_generator")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "after_statement",
            PointSelector::new("after_generator()")
                .procedure("use_generator")
                .anchor_occurrence(0),
        )
        .bind(
            "after_invoke",
            PointSelector::new("after_generator()")
                .procedure("use_generator")
                .effect("invoke"),
        )
        .bind(
            "exceptional_exit",
            PointSelector::new("def use_generator():")
                .procedure("use_generator")
                .effect("exceptional_exit"),
        )
        .bind(
            "eager_entry",
            PointSelector::new("def use_eager():")
                .procedure("use_eager")
                .effect("entry"),
        )
        .bind(
            "source_eager_invoke",
            PointSelector::new("source_eager()")
                .procedure("use_eager")
                .effect("invoke"),
        )
        .bind(
            "source_eager_normal",
            PointSelector::new("source_eager()")
                .procedure("use_eager")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "source_eager_exceptional",
            PointSelector::new("source_eager()")
                .procedure("use_eager")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "eager_boundary",
            PointSelector::new("for item in source_eager")
                .procedure("use_eager")
                .effect("gap")
                .anchor_occurrence(1),
        )
        .bind(
            "consume_eager_invoke",
            PointSelector::new(
                "consume_eager([transform_eager(item) for item in source_eager() if keep_eager(item)])",
            )
            .procedure("use_eager")
            .effect("invoke"),
        )
        .bind(
            "after_eager_invoke",
            PointSelector::new("after_eager()")
                .procedure("use_eager")
                .effect("invoke"),
        );

    graph.assert_successors(
        "source_invoke",
        &[
            cfg_edge("source_normal", ControlEdgeKind::Normal),
            cfg_edge("source_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "source_normal",
        &[cfg_edge("generator_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "generator_boundary",
        &[cfg_edge("source_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "generator_boundary",
        &[cfg_edge("consume_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "consume_invoke",
        &[cfg_edge("generator_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "consume_invoke",
        &[
            cfg_edge("consume_normal", ControlEdgeKind::Normal),
            cfg_edge("consume_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "consume_normal",
        &[cfg_edge("after_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "after_statement",
        &[cfg_edge("consume_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "source_exceptional",
        &[cfg_edge("exceptional_exit", ControlEdgeKind::Exceptional)],
    );
    graph.assert_successors(
        "consume_exceptional",
        &[cfg_edge("exceptional_exit", ControlEdgeKind::Exceptional)],
    );
    for capability in [
        SemanticCapability::DeferredExecution,
        SemanticCapability::GeneratorSuspension,
        SemanticCapability::Calls,
        SemanticCapability::ExceptionalControlFlow,
    ] {
        let expected_kind = match capability {
            SemanticCapability::DeferredExecution | SemanticCapability::GeneratorSuspension => {
                SemanticGapKind::Unsupported
            }
            SemanticCapability::Calls | SemanticCapability::ExceptionalControlFlow => {
                SemanticGapKind::Unknown
            }
            _ => unreachable!("fixture lists only generator-expression gaps"),
        };
        graph.assert_point_gap("generator_boundary", capability, expected_kind);
    }
    for deferred_call in ["transform(item)", "keep(item)"] {
        let error = graph
            .try_bind(
                format!("deferred_{deferred_call}"),
                PointSelector::new(deferred_call)
                    .procedure("use_generator")
                    .effect("invoke")
                    .anchor_occurrence(1),
            )
            .expect_err("generator body and filters must remain deferred");
        assert!(error.to_string().contains("matched no semantic"));
    }
    graph.assert_reachable("entry", "source_invoke");
    graph.assert_reachable("source_normal", "after_invoke");
    graph.assert_unreachable("source_exceptional", "generator_boundary");

    graph.assert_successors(
        "source_eager_invoke",
        &[
            cfg_edge("source_eager_normal", ControlEdgeKind::Normal),
            cfg_edge("source_eager_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "source_eager_normal",
        &[cfg_edge("eager_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "eager_boundary",
        &[cfg_edge("source_eager_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "eager_boundary",
        SemanticCapability::NormalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "eager_boundary",
        SemanticCapability::Calls,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "eager_boundary",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_successors("eager_boundary", &[]);
    graph.assert_reachable("eager_entry", "source_eager_invoke");
    graph.assert_unreachable("eager_entry", "consume_eager_invoke");
    graph.assert_unreachable("eager_entry", "after_eager_invoke");
    for deferred_call in ["transform_eager(item)", "keep_eager(item)"] {
        let error = graph
            .try_bind(
                format!("deferred_{deferred_call}"),
                PointSelector::new(deferred_call)
                    .procedure("use_eager")
                    .effect("invoke")
                    .anchor_occurrence(1),
            )
            .expect_err("eager comprehension body and filters remain behind the boundary");
        assert!(error.to_string().contains("matched no semantic"));
    }

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn python_chained_comparisons_short_circuit_in_control_and_value_contexts() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "python/chained_comparisons.py",
            r#"def compare_branch():
    if first_branch() < middle_branch() < last_branch():
        branch_true()
    branch_done()

def compare_value():
    outcome = first_value() < middle_value() < last_value()
    consume_value(outcome)
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph =
        SemanticGraph::materialize(&project, &analyzer, "python/chained_comparisons.py");
    graph
        .bind(
            "branch_entry",
            PointSelector::new("def compare_branch():")
                .procedure("compare_branch")
                .effect("entry"),
        )
        .bind(
            "first_branch_invoke",
            PointSelector::new("first_branch()")
                .procedure("compare_branch")
                .effect("invoke"),
        )
        .bind(
            "first_branch_normal",
            PointSelector::new("first_branch()")
                .procedure("compare_branch")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "first_branch_exceptional",
            PointSelector::new("first_branch()")
                .procedure("compare_branch")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "middle_branch_expression",
            PointSelector::new("middle_branch()")
                .procedure("compare_branch")
                .anchor_occurrence(0),
        )
        .bind(
            "middle_branch_invoke",
            PointSelector::new("middle_branch()")
                .procedure("compare_branch")
                .effect("invoke"),
        )
        .bind(
            "middle_branch_normal",
            PointSelector::new("middle_branch()")
                .procedure("compare_branch")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "middle_branch_exceptional",
            PointSelector::new("middle_branch()")
                .procedure("compare_branch")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "first_branch_decision",
            PointSelector::new("<")
                .occurrence(0)
                .procedure("compare_branch")
                .anchor_occurrence(0)
                .outgoing_kind(ControlEdgeKind::ConditionalFalse),
        )
        .bind(
            "last_branch_expression",
            PointSelector::new("last_branch()")
                .procedure("compare_branch")
                .anchor_occurrence(0),
        )
        .bind(
            "last_branch_invoke",
            PointSelector::new("last_branch()")
                .procedure("compare_branch")
                .effect("invoke"),
        )
        .bind(
            "last_branch_normal",
            PointSelector::new("last_branch()")
                .procedure("compare_branch")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "last_branch_exceptional",
            PointSelector::new("last_branch()")
                .procedure("compare_branch")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "second_branch_decision",
            PointSelector::new("<")
                .occurrence(1)
                .procedure("compare_branch")
                .anchor_occurrence(0)
                .outgoing_kind(ControlEdgeKind::ConditionalFalse),
        )
        .bind(
            "branch_true_block",
            PointSelector::new("branch_true()")
                .procedure("compare_branch")
                .anchor_occurrence(0),
        )
        .bind(
            "branch_true_invoke",
            PointSelector::new("branch_true()")
                .procedure("compare_branch")
                .effect("invoke"),
        )
        .bind(
            "branch_true_normal",
            PointSelector::new("branch_true()")
                .procedure("compare_branch")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "branch_done_statement",
            PointSelector::new("branch_done()")
                .procedure("compare_branch")
                .anchor_occurrence(0),
        )
        .bind(
            "branch_done_invoke",
            PointSelector::new("branch_done()")
                .procedure("compare_branch")
                .effect("invoke"),
        )
        .bind(
            "value_entry",
            PointSelector::new("def compare_value():")
                .procedure("compare_value")
                .effect("entry"),
        )
        .bind(
            "first_value_invoke",
            PointSelector::new("first_value()")
                .procedure("compare_value")
                .effect("invoke"),
        )
        .bind(
            "first_value_normal",
            PointSelector::new("first_value()")
                .procedure("compare_value")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "first_value_exceptional",
            PointSelector::new("first_value()")
                .procedure("compare_value")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "middle_value_expression",
            PointSelector::new("middle_value()")
                .procedure("compare_value")
                .anchor_occurrence(0),
        )
        .bind(
            "middle_value_invoke",
            PointSelector::new("middle_value()")
                .procedure("compare_value")
                .effect("invoke"),
        )
        .bind(
            "middle_value_normal",
            PointSelector::new("middle_value()")
                .procedure("compare_value")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "middle_value_exceptional",
            PointSelector::new("middle_value()")
                .procedure("compare_value")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "first_value_decision",
            PointSelector::new("<")
                .occurrence(2)
                .procedure("compare_value")
                .anchor_occurrence(0)
                .outgoing_kind(ControlEdgeKind::ConditionalFalse),
        )
        .bind(
            "last_value_expression",
            PointSelector::new("last_value()")
                .procedure("compare_value")
                .anchor_occurrence(0),
        )
        .bind(
            "last_value_invoke",
            PointSelector::new("last_value()")
                .procedure("compare_value")
                .effect("invoke"),
        )
        .bind(
            "last_value_normal",
            PointSelector::new("last_value()")
                .procedure("compare_value")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "last_value_exceptional",
            PointSelector::new("last_value()")
                .procedure("compare_value")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "second_value_decision",
            PointSelector::new("<")
                .occurrence(3)
                .procedure("compare_value")
                .anchor_occurrence(0)
                .outgoing_kind(ControlEdgeKind::ConditionalFalse),
        )
        .bind(
            "value_merge",
            PointSelector::new("first_value() < middle_value() < last_value()")
                .procedure("compare_value")
                .anchor_occurrence(1)
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "consume_value_statement",
            PointSelector::new("consume_value(outcome)")
                .procedure("compare_value")
                .anchor_occurrence(0),
        )
        .bind(
            "consume_value_invoke",
            PointSelector::new("consume_value(outcome)")
                .procedure("compare_value")
                .effect("invoke"),
        );

    for (invoke, normal, exceptional) in [
        (
            "first_branch_invoke",
            "first_branch_normal",
            "first_branch_exceptional",
        ),
        (
            "middle_branch_invoke",
            "middle_branch_normal",
            "middle_branch_exceptional",
        ),
        (
            "last_branch_invoke",
            "last_branch_normal",
            "last_branch_exceptional",
        ),
        (
            "first_value_invoke",
            "first_value_normal",
            "first_value_exceptional",
        ),
        (
            "middle_value_invoke",
            "middle_value_normal",
            "middle_value_exceptional",
        ),
        (
            "last_value_invoke",
            "last_value_normal",
            "last_value_exceptional",
        ),
    ] {
        graph.assert_successors(
            invoke,
            &[
                cfg_edge(normal, ControlEdgeKind::Normal),
                cfg_edge(exceptional, ControlEdgeKind::Exceptional),
            ],
        );
    }
    for decision in [
        "first_branch_decision",
        "second_branch_decision",
        "first_value_decision",
        "second_value_decision",
    ] {
        graph.assert_point_gap(
            decision,
            SemanticCapability::Calls,
            SemanticGapKind::Unknown,
        );
        graph.assert_point_gap(
            decision,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
        );
    }

    graph.assert_successors(
        "first_branch_normal",
        &[cfg_edge(
            "middle_branch_expression",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_predecessors(
        "middle_branch_expression",
        &[cfg_edge("first_branch_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "middle_branch_normal",
        &[cfg_edge("first_branch_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "first_branch_decision",
        &[cfg_edge("middle_branch_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "first_branch_decision",
        &[
            cfg_edge("last_branch_expression", ControlEdgeKind::ConditionalTrue),
            cfg_edge("branch_done_statement", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_predecessors(
        "last_branch_expression",
        &[cfg_edge(
            "first_branch_decision",
            ControlEdgeKind::ConditionalTrue,
        )],
    );
    graph.assert_successors(
        "last_branch_normal",
        &[cfg_edge("second_branch_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "second_branch_decision",
        &[cfg_edge("last_branch_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "second_branch_decision",
        &[
            cfg_edge("branch_true_block", ControlEdgeKind::ConditionalTrue),
            cfg_edge("branch_done_statement", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_reachable("branch_true_block", "branch_true_invoke");
    graph.assert_successors(
        "branch_true_normal",
        &[cfg_edge("branch_done_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "branch_done_statement",
        &[
            cfg_edge("branch_true_normal", ControlEdgeKind::Normal),
            cfg_edge("first_branch_decision", ControlEdgeKind::ConditionalFalse),
            cfg_edge("second_branch_decision", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_reachable("branch_entry", "branch_done_invoke");
    graph.assert_unreachable("branch_done_statement", "last_branch_invoke");

    graph.assert_successors(
        "first_value_normal",
        &[cfg_edge("middle_value_expression", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "middle_value_expression",
        &[cfg_edge("first_value_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "middle_value_normal",
        &[cfg_edge("first_value_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "first_value_decision",
        &[
            cfg_edge("last_value_expression", ControlEdgeKind::ConditionalTrue),
            cfg_edge("value_merge", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_predecessors(
        "last_value_expression",
        &[cfg_edge(
            "first_value_decision",
            ControlEdgeKind::ConditionalTrue,
        )],
    );
    graph.assert_successors(
        "last_value_normal",
        &[cfg_edge("second_value_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "second_value_decision",
        &[
            cfg_edge("value_merge", ControlEdgeKind::ConditionalTrue),
            cfg_edge("value_merge", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_predecessors(
        "value_merge",
        &[
            cfg_edge("first_value_decision", ControlEdgeKind::ConditionalFalse),
            cfg_edge("second_value_decision", ControlEdgeKind::ConditionalTrue),
            cfg_edge("second_value_decision", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "value_merge",
        &[cfg_edge("consume_value_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "consume_value_statement",
        &[cfg_edge("value_merge", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("value_entry", "consume_value_invoke");
    graph.assert_unreachable("consume_value_statement", "last_value_invoke");

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn python_assert_indexed_loop_targets_and_truth_tests_preserve_control_order() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "python/review_control.py",
            r#"def checked():
    assert condition(), message()
    after_assert()

def assign_each(values, sink):
    for sink[index()] in values:
        body()
    after_loop()

def truthy(truth_subject):
    if truth_subject:
        on_true()
    after_truth()
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "python/review_control.py");
    graph
        .bind(
            "assert_entry",
            PointSelector::new("assert condition(), message()")
                .procedure("checked")
                .effect("gap")
                .anchor_occurrence(0),
        )
        .bind(
            "condition_invoke",
            PointSelector::new("condition()")
                .procedure("checked")
                .effect("invoke"),
        )
        .bind(
            "condition_normal",
            PointSelector::new("condition()")
                .procedure("checked")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "condition_exceptional",
            PointSelector::new("condition()")
                .procedure("checked")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "condition_decision",
            PointSelector::new("condition()")
                .procedure("checked")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::ConditionalFalse),
        )
        .bind(
            "message_entry",
            PointSelector::new("assert condition(), message()")
                .procedure("checked")
                .anchor_occurrence(2)
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "message_expression",
            PointSelector::new("message()")
                .procedure("checked")
                .anchor_occurrence(0),
        )
        .bind(
            "message_invoke",
            PointSelector::new("message()")
                .procedure("checked")
                .effect("invoke"),
        )
        .bind(
            "message_normal",
            PointSelector::new("message()")
                .procedure("checked")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "message_exceptional",
            PointSelector::new("message()")
                .procedure("checked")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "assert_failure",
            PointSelector::new("assert condition(), message()")
                .procedure("checked")
                .effect("throw"),
        )
        .bind(
            "after_assert_statement",
            PointSelector::new("after_assert()")
                .procedure("checked")
                .anchor_occurrence(0),
        )
        .bind(
            "after_assert_invoke",
            PointSelector::new("after_assert()")
                .procedure("checked")
                .effect("invoke"),
        )
        .bind(
            "checked_exceptional_exit",
            PointSelector::new("def checked():")
                .procedure("checked")
                .effect("exceptional_exit"),
        )
        .bind(
            "loop_entry",
            PointSelector::new("def assign_each(values, sink):")
                .procedure("assign_each")
                .effect("entry"),
        )
        .bind(
            "loop_dispatch",
            PointSelector::new("for sink[index()] in values:")
                .procedure("assign_each")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "target_entry",
            PointSelector::new("sink[index()]")
                .procedure("assign_each")
                .anchor_occurrence(0),
        )
        .bind(
            "target_evaluation",
            PointSelector::new("sink[index()]")
                .procedure("assign_each")
                .effect("gap")
                .anchor_occurrence(2),
        )
        .bind(
            "index_invoke",
            PointSelector::new("index()")
                .procedure("assign_each")
                .effect("invoke"),
        )
        .bind(
            "index_normal",
            PointSelector::new("index()")
                .procedure("assign_each")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "index_exceptional",
            PointSelector::new("index()")
                .procedure("assign_each")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "target_binding",
            PointSelector::new("sink[index()]")
                .procedure("assign_each")
                .effect("gap")
                .anchor_occurrence(1)
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "loop_body_block",
            PointSelector::new("body()")
                .procedure("assign_each")
                .anchor_occurrence(0),
        )
        .bind(
            "loop_body_invoke",
            PointSelector::new("body()")
                .procedure("assign_each")
                .effect("invoke"),
        )
        .bind(
            "loop_body_normal",
            PointSelector::new("body()")
                .procedure("assign_each")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "after_loop_statement",
            PointSelector::new("after_loop()")
                .procedure("assign_each")
                .anchor_occurrence(0),
        )
        .bind(
            "after_loop_invoke",
            PointSelector::new("after_loop()")
                .procedure("assign_each")
                .effect("invoke"),
        )
        .bind(
            "truth_entry",
            PointSelector::new("def truthy(truth_subject):")
                .procedure("truthy")
                .effect("entry"),
        )
        .bind(
            "truth_decision",
            PointSelector::new("truth_subject")
                .occurrence(1)
                .procedure("truthy")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::ConditionalFalse),
        )
        .bind(
            "truth_body_block",
            PointSelector::new("on_true()")
                .procedure("truthy")
                .anchor_occurrence(0),
        )
        .bind(
            "truth_body_invoke",
            PointSelector::new("on_true()")
                .procedure("truthy")
                .effect("invoke"),
        )
        .bind(
            "truth_body_normal",
            PointSelector::new("on_true()")
                .procedure("truthy")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "after_truth_statement",
            PointSelector::new("after_truth()")
                .procedure("truthy")
                .anchor_occurrence(0),
        )
        .bind(
            "after_truth_invoke",
            PointSelector::new("after_truth()")
                .procedure("truthy")
                .effect("invoke"),
        );

    graph.assert_point_gap(
        "assert_entry",
        SemanticCapability::NormalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_successors(
        "condition_invoke",
        &[
            cfg_edge("condition_normal", ControlEdgeKind::Normal),
            cfg_edge("condition_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "condition_normal",
        &[cfg_edge("condition_decision", ControlEdgeKind::Normal)],
    );
    for capability in [
        SemanticCapability::Calls,
        SemanticCapability::ExceptionalControlFlow,
    ] {
        let kind = if capability == SemanticCapability::Calls {
            SemanticGapKind::Unknown
        } else {
            SemanticGapKind::Unsupported
        };
        graph.assert_point_gap("condition_decision", capability, kind);
    }
    graph.assert_successors(
        "condition_decision",
        &[
            cfg_edge("after_assert_statement", ControlEdgeKind::ConditionalTrue),
            cfg_edge("message_entry", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_predecessors(
        "after_assert_statement",
        &[cfg_edge(
            "condition_decision",
            ControlEdgeKind::ConditionalTrue,
        )],
    );
    graph.assert_predecessors(
        "message_entry",
        &[cfg_edge(
            "condition_decision",
            ControlEdgeKind::ConditionalFalse,
        )],
    );
    graph.assert_successors(
        "message_entry",
        &[cfg_edge("message_expression", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "message_invoke",
        &[
            cfg_edge("message_normal", ControlEdgeKind::Normal),
            cfg_edge("message_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "message_normal",
        &[cfg_edge("assert_failure", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "assert_failure",
        &[cfg_edge("message_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "assert_failure",
        &[cfg_edge(
            "checked_exceptional_exit",
            ControlEdgeKind::Exceptional,
        )],
    );
    graph.assert_successors(
        "condition_exceptional",
        &[cfg_edge(
            "checked_exceptional_exit",
            ControlEdgeKind::Exceptional,
        )],
    );
    graph.assert_successors(
        "message_exceptional",
        &[cfg_edge(
            "checked_exceptional_exit",
            ControlEdgeKind::Exceptional,
        )],
    );
    graph.assert_reachable("assert_entry", "after_assert_invoke");
    graph.assert_unreachable("message_entry", "after_assert_statement");

    graph.assert_point_gap(
        "loop_dispatch",
        SemanticCapability::Calls,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "loop_dispatch",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors(
        "loop_dispatch",
        &[
            cfg_edge("target_entry", ControlEdgeKind::ConditionalTrue),
            cfg_edge("after_loop_statement", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_predecessors(
        "target_entry",
        &[cfg_edge("loop_dispatch", ControlEdgeKind::ConditionalTrue)],
    );
    graph.assert_successors(
        "target_entry",
        &[cfg_edge("target_evaluation", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("target_evaluation", "index_invoke");
    graph.assert_successors(
        "index_invoke",
        &[
            cfg_edge("index_normal", ControlEdgeKind::Normal),
            cfg_edge("index_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "index_normal",
        &[cfg_edge("target_binding", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "target_binding",
        &[cfg_edge("index_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "target_binding",
        SemanticCapability::Calls,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "target_binding",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors(
        "target_binding",
        &[cfg_edge("loop_body_block", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("loop_body_block", "loop_body_invoke");
    graph.assert_successors(
        "loop_body_normal",
        &[cfg_edge("loop_dispatch", ControlEdgeKind::LoopBack)],
    );
    graph.assert_predecessors(
        "after_loop_statement",
        &[cfg_edge("loop_dispatch", ControlEdgeKind::ConditionalFalse)],
    );
    graph.assert_reachable("loop_entry", "after_loop_invoke");
    graph.assert_unreachable("after_loop_statement", "index_invoke");

    graph.assert_point_gap(
        "truth_decision",
        SemanticCapability::Calls,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "truth_decision",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors(
        "truth_decision",
        &[
            cfg_edge("truth_body_block", ControlEdgeKind::ConditionalTrue),
            cfg_edge("after_truth_statement", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_reachable("truth_body_block", "truth_body_invoke");
    graph.assert_successors(
        "truth_body_normal",
        &[cfg_edge("after_truth_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "after_truth_statement",
        &[
            cfg_edge("truth_body_normal", ControlEdgeKind::Normal),
            cfg_edge("truth_decision", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_reachable("truth_entry", "after_truth_invoke");

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn python_resource_generator_match_and_async_boundaries_are_typed() {
    let project = InlineTestProject::with_language(Language::Python)
        .file(
            "python/boundaries.py",
            r#"def managed():
    with acquire() as resource:
        use(resource)
    after_with()

async def async_managed():
    async with acquire_async() as resource:
        use_async(resource)
    after_async_with()

def values():
    yield produce()
    after_yield()

def choose(value):
    match value:
        case 0:
            zero()
        case _:
            other()
    after_match()

async def await_one():
    result = await fetch()
    after_await(result)

async def iterate(items):
    async for item in items:
        consume(item)
    after_async_for()
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "python/boundaries.py");
    graph
        .bind(
            "managed_entry",
            PointSelector::new("def managed():")
                .procedure("managed")
                .effect("entry"),
        )
        .bind(
            "acquire_invoke",
            PointSelector::new("acquire()")
                .procedure("managed")
                .effect("invoke"),
        )
        .bind(
            "acquire_normal",
            PointSelector::new("acquire()")
                .procedure("managed")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "acquire_exceptional",
            PointSelector::new("acquire()")
                .procedure("managed")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "with_boundary",
            PointSelector::new("acquire() as resource")
                .procedure("managed")
                .effect("gap")
                .anchor_occurrence(0),
        )
        .bind(
            "after_with",
            PointSelector::new("after_with()")
                .procedure("managed")
                .effect("invoke"),
        )
        .bind(
            "async_managed_entry",
            PointSelector::new("async def async_managed():")
                .procedure("async_managed")
                .effect("entry"),
        )
        .bind(
            "acquire_async_invoke",
            PointSelector::new("acquire_async()")
                .procedure("async_managed")
                .effect("invoke"),
        )
        .bind(
            "acquire_async_normal",
            PointSelector::new("acquire_async()")
                .procedure("async_managed")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "acquire_async_exceptional",
            PointSelector::new("acquire_async()")
                .procedure("async_managed")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "async_with_boundary",
            PointSelector::new("acquire_async() as resource")
                .procedure("async_managed")
                .effect("gap")
                .anchor_occurrence(0),
        )
        .bind(
            "after_async_with",
            PointSelector::new("after_async_with()")
                .procedure("async_managed")
                .effect("invoke"),
        )
        .bind(
            "values_entry",
            PointSelector::new("def values():")
                .procedure("values")
                .effect("entry"),
        )
        .bind(
            "produce_invoke",
            PointSelector::new("produce()")
                .procedure("values")
                .effect("invoke"),
        )
        .bind(
            "produce_normal",
            PointSelector::new("produce()")
                .procedure("values")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "produce_exceptional",
            PointSelector::new("produce()")
                .procedure("values")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "yield_boundary",
            PointSelector::new("yield produce()")
                .procedure("values")
                .effect("gap"),
        )
        .bind(
            "after_yield",
            PointSelector::new("after_yield()")
                .procedure("values")
                .effect("invoke"),
        )
        .bind(
            "choose_entry",
            PointSelector::new("def choose(value):")
                .procedure("choose")
                .effect("entry"),
        )
        .bind(
            "match_statement",
            PointSelector::new(
                "match value:\n        case 0:\n            zero()\n        case _:\n            other()",
            )
            .procedure("choose")
            .anchor_occurrence(0),
        )
        .bind(
            "match_subject",
            PointSelector::new("value")
                .occurrence(2)
                .procedure("choose")
                .anchor_occurrence(0),
        )
        .bind(
            "match_boundary",
            PointSelector::new("match value:")
                .procedure("choose")
                .effect("gap"),
        )
        .bind(
            "after_match",
            PointSelector::new("after_match()")
                .procedure("choose")
                .effect("invoke"),
        )
        .bind(
            "await_entry",
            PointSelector::new("async def await_one():")
                .procedure("await_one")
                .effect("entry"),
        )
        .bind(
            "fetch_invoke",
            PointSelector::new("fetch()")
                .procedure("await_one")
                .effect("invoke"),
        )
        .bind(
            "fetch_normal",
            PointSelector::new("fetch()")
                .procedure("await_one")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "fetch_exceptional",
            PointSelector::new("fetch()")
                .procedure("await_one")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "await_suspend",
            PointSelector::new("await fetch()")
                .procedure("await_one")
                .effect("async_suspend"),
        )
        .bind(
            "await_normal_resume",
            PointSelector::new("await fetch()")
                .procedure("await_one")
                .effect("async_resume")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "await_exceptional_resume",
            PointSelector::new("await fetch()")
                .procedure("await_one")
                .effect("async_resume")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "after_await_statement",
            PointSelector::new("after_await(result)")
                .procedure("await_one")
                .anchor_occurrence(0),
        )
        .bind(
            "after_await_invoke",
            PointSelector::new("after_await(result)")
                .procedure("await_one")
                .effect("invoke"),
        )
        .bind(
            "await_exceptional_exit",
            PointSelector::new("async def await_one():")
                .procedure("await_one")
                .effect("exceptional_exit"),
        )
        .bind(
            "iterate_entry",
            PointSelector::new("async def iterate(items):")
                .procedure("iterate")
                .effect("entry"),
        )
        .bind(
            "async_for_statement",
            PointSelector::new("async for item in items:\n        consume(item)")
                .procedure("iterate")
                .anchor_occurrence(0),
        )
        .bind(
            "async_for_boundary",
            PointSelector::new("async for item in items:")
                .procedure("iterate")
                .effect("gap"),
        )
        .bind(
            "after_async_for",
            PointSelector::new("after_async_for()")
                .procedure("iterate")
                .effect("invoke"),
        );

    for (invoke, normal, exceptional) in [
        ("acquire_invoke", "acquire_normal", "acquire_exceptional"),
        (
            "acquire_async_invoke",
            "acquire_async_normal",
            "acquire_async_exceptional",
        ),
        ("produce_invoke", "produce_normal", "produce_exceptional"),
        ("fetch_invoke", "fetch_normal", "fetch_exceptional"),
    ] {
        graph.assert_successors(
            invoke,
            &[
                cfg_edge(normal, ControlEdgeKind::Normal),
                cfg_edge(exceptional, ControlEdgeKind::Exceptional),
            ],
        );
    }

    graph.assert_successors(
        "acquire_normal",
        &[cfg_edge("with_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "with_boundary",
        &[cfg_edge("acquire_normal", ControlEdgeKind::Normal)],
    );
    for capability in [
        SemanticCapability::ResourceManagement,
        SemanticCapability::Calls,
        SemanticCapability::ExceptionalControlFlow,
    ] {
        graph.assert_point_gap("with_boundary", capability, SemanticGapKind::Unsupported);
    }
    graph.assert_successors("with_boundary", &[]);
    graph.assert_reachable("managed_entry", "with_boundary");
    graph.assert_unreachable("managed_entry", "after_with");

    graph.assert_successors(
        "acquire_async_normal",
        &[cfg_edge("async_with_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "async_with_boundary",
        &[cfg_edge("acquire_async_normal", ControlEdgeKind::Normal)],
    );
    for capability in [
        SemanticCapability::ResourceManagement,
        SemanticCapability::Calls,
        SemanticCapability::ExceptionalControlFlow,
        SemanticCapability::AsyncSuspendResume,
    ] {
        graph.assert_point_gap(
            "async_with_boundary",
            capability,
            SemanticGapKind::Unsupported,
        );
    }
    graph.assert_successors("async_with_boundary", &[]);
    graph.assert_reachable("async_managed_entry", "async_with_boundary");
    graph.assert_unreachable("async_managed_entry", "after_async_with");

    graph.assert_successors(
        "produce_normal",
        &[cfg_edge("yield_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "yield_boundary",
        &[cfg_edge("produce_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "yield_boundary",
        SemanticCapability::GeneratorSuspension,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors("yield_boundary", &[]);
    graph.assert_reachable("values_entry", "yield_boundary");
    graph.assert_unreachable("values_entry", "after_yield");

    graph.assert_successors(
        "match_statement",
        &[cfg_edge("match_subject", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "match_subject",
        &[cfg_edge("match_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "match_boundary",
        &[cfg_edge("match_subject", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "match_boundary",
        SemanticCapability::NormalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "match_boundary",
        SemanticCapability::Calls,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "match_boundary",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors("match_boundary", &[]);
    graph.assert_reachable("choose_entry", "match_boundary");
    graph.assert_unreachable("choose_entry", "after_match");
    for branch_call in ["zero()", "other()"] {
        let error = graph
            .try_bind(
                format!("unscheduled_match_{branch_call}"),
                PointSelector::new(branch_call)
                    .procedure("choose")
                    .effect("invoke"),
            )
            .expect_err("unsupported match cases must not be guessed");
        assert!(error.to_string().contains("matched no semantic"));
    }

    graph.assert_successors(
        "fetch_normal",
        &[cfg_edge("await_suspend", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "await_suspend",
        &[
            cfg_edge("await_normal_resume", ControlEdgeKind::AsyncNormal),
            cfg_edge(
                "await_exceptional_resume",
                ControlEdgeKind::AsyncExceptional,
            ),
        ],
    );
    graph.assert_predecessors(
        "await_normal_resume",
        &[cfg_edge("await_suspend", ControlEdgeKind::AsyncNormal)],
    );
    graph.assert_predecessors(
        "await_exceptional_resume",
        &[cfg_edge("await_suspend", ControlEdgeKind::AsyncExceptional)],
    );
    graph.assert_successors(
        "await_normal_resume",
        &[cfg_edge("after_await_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "await_exceptional_resume",
        &[cfg_edge(
            "await_exceptional_exit",
            ControlEdgeKind::Exceptional,
        )],
    );
    graph.assert_successors(
        "fetch_exceptional",
        &[cfg_edge(
            "await_exceptional_exit",
            ControlEdgeKind::Exceptional,
        )],
    );
    graph.assert_reachable("after_await_statement", "after_await_invoke");
    graph.assert_reachable("await_entry", "after_await_invoke");
    graph.assert_reachable("await_entry", "await_exceptional_exit");

    graph.assert_successors(
        "async_for_statement",
        &[cfg_edge("async_for_boundary", ControlEdgeKind::Normal)],
    );
    for capability in [
        SemanticCapability::Calls,
        SemanticCapability::ExceptionalControlFlow,
        SemanticCapability::ResourceManagement,
        SemanticCapability::AsyncSuspendResume,
    ] {
        graph.assert_point_gap(
            "async_for_boundary",
            capability,
            SemanticGapKind::Unsupported,
        );
    }
    graph.assert_successors("async_for_boundary", &[]);
    graph.assert_reachable("iterate_entry", "async_for_boundary");
    graph.assert_unreachable("iterate_entry", "after_async_for");

    for (name, expected_async, expected_generator) in [
        ("async_managed", true, false),
        ("values", false, true),
        ("await_one", true, false),
        ("iterate", true, false),
    ] {
        let procedure = graph
            .artifact()
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some(name)
            })
            .unwrap_or_else(|| panic!("missing Python procedure {name}"));
        assert_eq!(procedure.properties().is_async, expected_async);
        assert_eq!(procedure.properties().is_generator, expected_generator);
        assert_eq!(
            procedure.properties().invocation,
            if expected_async || expected_generator {
                ProcedureInvocationKind::Deferred
            } else {
                ProcedureInvocationKind::Immediate
            }
        );
    }

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn php_direct_free_call_conformance() {
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::Php,
        dialect: SemanticLanguage::Standard(Language::Php),
        callee_path: "src/Leaf.php",
        callee_source: r#"<?php
            namespace App;

            function php_leaf(): int {
                return 7;
            }
        "#,
        callee_declaration: "function php_leaf(): int",
        callee_name: "php_leaf",
        caller_path: "src/Caller.php",
        caller_source: r#"<?php
            namespace App;

            function php_root(): int {
                return php_leaf();
            }
        "#,
        caller_declaration: "function php_root(): int",
        caller_name: "php_root",
        call: "php_leaf()",
    });
}

#[test]
fn php_typed_instance_method_call_uses_the_shared_dispatch_oracle() {
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::Php,
        dialect: SemanticLanguage::Standard(Language::Php),
        callee_path: "src/Service.php",
        callee_source: r#"<?php
            namespace App;

            final class Service {
                public function run(): int {
                    return 7;
                }
            }
        "#,
        callee_declaration: "public function run(): int",
        callee_name: "run",
        caller_path: "src/Controller.php",
        caller_source: r#"<?php
            namespace App;

            final class Controller {
                public function handle(Service $service): int {
                    return $service->run();
                }
            }
        "#,
        caller_declaration: "public function handle(Service $service): int",
        caller_name: "handle",
        call: "$service->run()",
    });
}

#[test]
fn php_typed_nullsafe_method_call_has_matched_icfg_returns() {
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::Php,
        dialect: SemanticLanguage::Standard(Language::Php),
        callee_path: "src/NullableService.php",
        callee_source: r#"<?php
            namespace App;

            final class NullableService {
                public function run(): int {
                    return 7;
                }
            }
        "#,
        callee_declaration: "public function run(): int",
        callee_name: "run",
        caller_path: "src/NullableController.php",
        caller_source: r#"<?php
            namespace App;

            function maybe_run(?NullableService $service): ?int {
                return $service?->run();
            }
        "#,
        caller_declaration: "function maybe_run(?NullableService $service): ?int",
        caller_name: "maybe_run",
        call: "$service?->run()",
    });
}

#[test]
fn php_named_nested_and_anonymous_callables_are_separate() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Callables.php",
            r#"<?php
                namespace App;

                function top_level(): void {
                    top_body();
                }

                final class Worker {
                    public function __construct() {
                        constructor_body();
                    }

                    public function step(): void {
                        method_body();
                    }

                    public static function create(): void {
                        static_body();
                    }

                    public string $value {
                        #[Hook]
                        final get => getter_body();
                    }
                }

                function outer(): void {
                    function local(): void {
                        local_body();
                    }

                    $closure = function (): void {
                        closure_body();
                    };
                    $arrow = fn(): int => arrow_body();
                    outer_body();
                }

                function values(): iterable {
                    yield yielded_value();
                    after_yield();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/Callables.php");

    for (alias, declaration, procedure, body_call) in [
        (
            "top",
            "function top_level(): void",
            "top_level",
            "top_body()",
        ),
        (
            "constructor",
            "public function __construct()",
            "__construct",
            "constructor_body()",
        ),
        (
            "method",
            "public function step(): void",
            "step",
            "method_body()",
        ),
        (
            "static_method",
            "public static function create(): void",
            "create",
            "static_body()",
        ),
        (
            "accessor",
            "final get => getter_body()",
            "$value.get",
            "getter_body()",
        ),
        ("local", "function local(): void", "local", "local_body()"),
        ("closure", "function (): void", "$closure", "closure_body()"),
        ("arrow", "fn(): int", "$arrow", "arrow_body()"),
        ("outer", "function outer(): void", "outer", "outer_body()"),
        (
            "generator",
            "function values(): iterable",
            "values",
            "yielded_value()",
        ),
    ] {
        graph
            .bind(
                format!("{alias}_entry"),
                PointSelector::new(declaration)
                    .procedure(procedure)
                    .effect("entry"),
            )
            .bind(
                format!("{alias}_invoke"),
                PointSelector::new(body_call)
                    .procedure(procedure)
                    .effect("invoke"),
            );
        graph.assert_reachable(&format!("{alias}_entry"), &format!("{alias}_invoke"));
    }

    for body_call in [
        "local_body()",
        "closure_body()",
        "arrow_body()",
        "yielded_value()",
    ] {
        let error = graph
            .try_bind(
                format!("outer_must_not_own_{body_call}"),
                PointSelector::new(body_call)
                    .procedure("outer")
                    .effect("invoke"),
            )
            .expect_err("nested callable execution must stay outside the enclosing CFG");
        assert!(
            error.to_string().contains("matched no semantic"),
            "unexpected PHP nested callable selector for {body_call}: {error}"
        );
    }

    let procedures = graph.artifact().procedures();
    let named = |name: &str, kind: ProcedureKind| {
        procedures
            .iter()
            .find(|procedure| {
                procedure.kind() == kind
                    && procedure
                        .locator()
                        .declaration()
                        .segments()
                        .last()
                        .and_then(|segment| segment.name())
                        == Some(name)
            })
            .unwrap_or_else(|| panic!("missing PHP {kind:?} procedure {name}"))
    };
    let top = named("top_level", ProcedureKind::Function);
    let constructor = named("__construct", ProcedureKind::Constructor);
    let method = named("step", ProcedureKind::Method);
    let static_method = named("create", ProcedureKind::Method);
    let accessor = named("$value.get", ProcedureKind::Accessor);
    let outer = named("outer", ProcedureKind::Function);
    let local = named("local", ProcedureKind::LocalFunction);
    let closure = named("$closure", ProcedureKind::Closure);
    let arrow = named("$arrow", ProcedureKind::Lambda);
    let generator = named("values", ProcedureKind::Function);

    for procedure in [top, constructor, method, static_method, accessor, outer] {
        assert!(procedure.lexical_parent().is_none());
    }
    for procedure in [local, closure, arrow] {
        assert_eq!(procedure.lexical_parent(), Some(outer.id()));
    }
    assert!(!constructor.properties().is_static);
    assert!(!method.properties().is_static);
    assert!(static_method.properties().is_static);
    for procedure in [
        top,
        constructor,
        method,
        static_method,
        accessor,
        outer,
        local,
        closure,
        arrow,
    ] {
        assert!(!procedure.properties().is_generator);
        assert_eq!(
            procedure.properties().invocation,
            ProcedureInvocationKind::Immediate
        );
    }
    assert!(generator.properties().is_generator);
    assert_eq!(
        generator.properties().invocation,
        ProcedureInvocationKind::Deferred
    );
    assert!(
        arrow
            .points()
            .iter()
            .any(|point| point.events.iter().any(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::ProcedureReturn { value: Some(_) }
                )
            })),
        "PHP arrow expressions must publish an implicit value return"
    );
    assert!(
        accessor
            .points()
            .iter()
            .any(|point| point.events.iter().any(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::ProcedureReturn { value: Some(_) }
                )
            })),
        "attributed/final expression-bodied PHP getters must retain their hook identity and implicit value return"
    );

    graph
        .bind(
            "yield_boundary",
            PointSelector::new("yield yielded_value()")
                .procedure("values")
                .effect("gap"),
        )
        .bind(
            "after_yield",
            PointSelector::new("after_yield()")
                .procedure("values")
                .effect("invoke"),
        );
    graph.assert_point_gap(
        "yield_boundary",
        SemanticCapability::GeneratorSuspension,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors("yield_boundary", &[]);
    graph.assert_unreachable("generator_entry", "after_yield");

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn php_branches_loops_and_numeric_abrupt_completions_have_exact_topology() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Control.php",
            r#"<?php
                function branch(bool $flag): void {
                    before();
                    if ($flag) {
                        yes();
                        return;
                        dead_after_return();
                    } else {
                        no();
                    }
                    after();
                }

                function nested_levels(bool $outer, bool $inner, bool $repeat): void {
                    while ($outer) {
                        while ($inner) {
                            if ($repeat) {
                                continue 2;
                            }
                            break 2;
                        }
                        dead_after_transfer();
                    }
                    after_nested();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/Control.php");
    graph
        .bind(
            "branch_entry",
            PointSelector::new("function branch(bool $flag)")
                .procedure("branch")
                .effect("entry"),
        )
        .bind(
            "condition",
            PointSelector::new("$flag")
                .occurrence(1)
                .procedure("branch")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "yes_block",
            PointSelector::new(
                r#"{
                        yes();
                        return;
                        dead_after_return();
                    }"#,
            )
            .procedure("branch")
            .anchor_occurrence(0),
        )
        .bind(
            "yes_statement",
            PointSelector::new("yes()")
                .procedure("branch")
                .anchor_occurrence(0),
        )
        .bind(
            "no_block",
            PointSelector::new(
                r#"{
                        no();
                    }"#,
            )
            .procedure("branch")
            .anchor_occurrence(0),
        )
        .bind(
            "no_statement",
            PointSelector::new("no()")
                .procedure("branch")
                .anchor_occurrence(0),
        )
        .bind(
            "no_normal",
            PointSelector::new("no()")
                .procedure("branch")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "return",
            PointSelector::new("return;")
                .procedure("branch")
                .effect("procedure_return"),
        )
        .bind(
            "branch_normal_exit",
            PointSelector::new("function branch(bool $flag)")
                .procedure("branch")
                .effect("normal_exit"),
        )
        .bind(
            "yes_full_statement",
            PointSelector::new("yes();")
                .procedure("branch")
                .anchor_occurrence(0),
        )
        .bind(
            "no_full_statement",
            PointSelector::new("no();")
                .procedure("branch")
                .anchor_occurrence(0),
        )
        .bind(
            "after_full_statement",
            PointSelector::new("after();")
                .procedure("branch")
                .anchor_occurrence(0),
        )
        .bind(
            "after_statement",
            PointSelector::new("after()")
                .procedure("branch")
                .anchor_occurrence(0),
        )
        .bind(
            "after_invoke",
            PointSelector::new("after()")
                .procedure("branch")
                .effect("invoke"),
        )
        .bind(
            "dead_after_return",
            PointSelector::new("dead_after_return()")
                .procedure("branch")
                .effect("invoke"),
        )
        .bind(
            "outer_condition",
            PointSelector::new("$outer")
                .occurrence(1)
                .procedure("nested_levels")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "outer_condition_entry",
            PointSelector::new("($outer)")
                .procedure("nested_levels")
                .outgoing_kind(ControlEdgeKind::Normal)
                .anchor_occurrence(0),
        )
        .bind(
            "outer_body",
            PointSelector::new(
                r#"{
                        while ($inner) {
                            if ($repeat) {
                                continue 2;
                            }
                            break 2;
                        }
                        dead_after_transfer();
                    }"#,
            )
            .procedure("nested_levels")
            .anchor_occurrence(0),
        )
        .bind(
            "continue_two",
            PointSelector::new("continue 2;")
                .procedure("nested_levels")
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "break_two",
            PointSelector::new("break 2;")
                .procedure("nested_levels")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "dead_after_transfer",
            PointSelector::new("dead_after_transfer()")
                .procedure("nested_levels")
                .effect("invoke"),
        )
        .bind(
            "after_nested_statement",
            PointSelector::new("after_nested()")
                .procedure("nested_levels")
                .anchor_occurrence(0),
        )
        .bind(
            "after_nested_full_statement",
            PointSelector::new("after_nested();")
                .procedure("nested_levels")
                .anchor_occurrence(0),
        )
        .bind(
            "after_nested_invoke",
            PointSelector::new("after_nested()")
                .procedure("nested_levels")
                .effect("invoke"),
        );

    graph.assert_successors(
        "condition",
        &[
            cfg_edge("yes_block", ControlEdgeKind::ConditionalTrue),
            cfg_edge("no_block", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "yes_block",
        &[cfg_edge("yes_full_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "yes_full_statement",
        &[cfg_edge("yes_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "no_block",
        &[cfg_edge("no_full_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "no_full_statement",
        &[cfg_edge("no_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "after_full_statement",
        &[cfg_edge("no_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "after_full_statement",
        &[cfg_edge("after_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "return",
        &[cfg_edge("branch_normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("branch_entry", "after_invoke");
    graph.assert_unreachable("return", "after_invoke");
    graph.assert_unreachable("branch_entry", "dead_after_return");

    graph.assert_successors(
        "outer_condition",
        &[
            cfg_edge("outer_body", ControlEdgeKind::ConditionalTrue),
            cfg_edge(
                "after_nested_full_statement",
                ControlEdgeKind::ConditionalFalse,
            ),
        ],
    );
    graph.assert_successors(
        "continue_two",
        &[cfg_edge("outer_condition_entry", ControlEdgeKind::LoopBack)],
    );
    graph.assert_successors(
        "outer_condition_entry",
        &[cfg_edge("outer_condition", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "break_two",
        &[cfg_edge(
            "after_nested_full_statement",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_successors(
        "after_nested_full_statement",
        &[cfg_edge("after_nested_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_unreachable("break_two", "dead_after_transfer");
    graph.assert_reachable("break_two", "after_nested_invoke");

    graph.assert_adjacency_symmetric();
}

#[test]
fn php_first_class_callable_is_not_invoked_but_dynamic_calls_remain_boundaries() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/InvocationForms.php",
            r#"<?php
                function target(): void {}

                function nested(): int {
                    return 1;
                }

                function invocation_forms(callable $dynamic): void {
                    $reference = target(...);
                    $dynamic(nested());
                    after_dynamic();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/InvocationForms.php");
    graph
        .bind(
            "entry",
            PointSelector::new("function invocation_forms(callable $dynamic)")
                .procedure("invocation_forms")
                .effect("entry"),
        )
        .bind(
            "callable_reference",
            PointSelector::new("target(...)")
                .procedure("invocation_forms")
                .effect("callable_reference"),
        )
        .bind(
            "nested_invoke",
            PointSelector::new("nested()")
                .procedure("invocation_forms")
                .effect("invoke"),
        )
        .bind(
            "nested_normal",
            PointSelector::new("nested()")
                .procedure("invocation_forms")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "dynamic_invoke",
            PointSelector::new("$dynamic(nested())")
                .procedure("invocation_forms")
                .effect("invoke"),
        )
        .bind(
            "dynamic_normal",
            PointSelector::new("$dynamic(nested())")
                .procedure("invocation_forms")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "dynamic_exceptional",
            PointSelector::new("$dynamic(nested())")
                .procedure("invocation_forms")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "after_dynamic_statement",
            PointSelector::new("after_dynamic()")
                .procedure("invocation_forms")
                .anchor_occurrence(0),
        )
        .bind(
            "after_dynamic_full_statement",
            PointSelector::new("after_dynamic();")
                .procedure("invocation_forms")
                .anchor_occurrence(0),
        )
        .bind(
            "after_dynamic_invoke",
            PointSelector::new("after_dynamic()")
                .procedure("invocation_forms")
                .effect("invoke"),
        );

    let error = graph
        .try_bind(
            "fabricated_reference_invoke",
            PointSelector::new("target(...)")
                .procedure("invocation_forms")
                .effect("invoke"),
        )
        .expect_err("PHP first-class callable syntax must not be an invocation");
    assert!(
        error.to_string().contains("matched no semantic"),
        "unexpected first-class callable selector: {error}"
    );
    graph.assert_reachable("entry", "callable_reference");
    graph.assert_successors(
        "nested_normal",
        &[cfg_edge("dynamic_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "dynamic_invoke",
        &[cfg_edge("nested_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "dynamic_invoke",
        &[
            cfg_edge("dynamic_normal", ControlEdgeKind::Normal),
            cfg_edge("dynamic_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "dynamic_normal",
        &[cfg_edge(
            "after_dynamic_full_statement",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_successors(
        "after_dynamic_full_statement",
        &[cfg_edge("after_dynamic_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("nested_invoke", "after_dynamic_invoke");
    graph.assert_adjacency_symmetric();

    let mut icfg = IcfgGraph::materialize(
        &project,
        &analyzer,
        "src/InvocationForms.php",
        PointSelector::new("function invocation_forms(callable $dynamic)")
            .procedure("invocation_forms")
            .effect("entry"),
    );
    icfg.bind_call(
        "dynamic_call",
        "src/InvocationForms.php",
        PointSelector::new("$dynamic(nested())")
            .procedure("invocation_forms")
            .effect("invoke"),
    )
    .bind_node(
        "icfg_dynamic_invoke",
        "src/InvocationForms.php",
        PointSelector::new("$dynamic(nested())")
            .procedure("invocation_forms")
            .effect("invoke"),
        root(),
    );
    icfg.assert_outcome(IcfgOutcomeKind::Unknown);
    icfg.assert_boundary(
        "icfg_dynamic_invoke",
        ExpectedIcfgBoundary::new(ExpectedIcfgBoundaryKind::DispatchUnresolved)
            .originating_call("dynamic_call"),
    );
    icfg.assert_successors("icfg_dynamic_invoke", &[]);
    icfg.assert_adjacency_symmetric();
}

#[test]
fn php_first_class_callable_requires_a_sole_placeholder_argument() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/RecoveredPlaceholder.php",
            r#"<?php
                function target(): void {}

                function recovered_placeholder(): void {
                    target(..., recovered_argument());
                    after_recovered_call();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/RecoveredPlaceholder.php");
    graph
        .bind(
            "recovered_outer_invoke",
            PointSelector::new("target(..., recovered_argument())")
                .procedure("recovered_placeholder")
                .effect("invoke"),
        )
        .bind(
            "after_recovered_invoke",
            PointSelector::new("after_recovered_call()")
                .procedure("recovered_placeholder")
                .effect("invoke"),
        );

    graph.assert_reachable("recovered_outer_invoke", "after_recovered_invoke");
    graph.assert_adjacency_symmetric();
}

#[test]
fn php_nullsafe_calls_skip_arguments_and_short_circuit_calls_preserve_order() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/ConditionalCalls.php",
            r#"<?php
                final class Service {
                    public function run(int $value): void {}
                }

                function maybe_run(?Service $service): void {
                    $service?->run(argument());
                    after_nullsafe();
                }

                function guarded(bool $flag): void {
                    if ($flag && first(second())) {
                        selected();
                    }
                    after_condition();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/ConditionalCalls.php");
    graph
        .bind(
            "nullsafe_decision",
            PointSelector::new("$service?->run(argument())")
                .procedure("maybe_run")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "argument_expression",
            PointSelector::new("argument()")
                .procedure("maybe_run")
                .anchor_occurrence(0),
        )
        .bind(
            "argument_normal",
            PointSelector::new("argument()")
                .procedure("maybe_run")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "nullsafe_invoke",
            PointSelector::new("$service?->run(argument())")
                .procedure("maybe_run")
                .effect("invoke"),
        )
        .bind(
            "nullsafe_normal",
            PointSelector::new("$service?->run(argument())")
                .procedure("maybe_run")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "nullsafe_exceptional",
            PointSelector::new("$service?->run(argument())")
                .procedure("maybe_run")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "after_nullsafe_statement",
            PointSelector::new("after_nullsafe()")
                .procedure("maybe_run")
                .anchor_occurrence(0),
        )
        .bind(
            "after_nullsafe_full_statement",
            PointSelector::new("after_nullsafe();")
                .procedure("maybe_run")
                .anchor_occurrence(0),
        )
        .bind(
            "flag_decision",
            PointSelector::new("$flag")
                .occurrence(1)
                .procedure("guarded")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "right_expression",
            PointSelector::new("first(second())")
                .procedure("guarded")
                .anchor_occurrence(0),
        )
        .bind(
            "first_callee",
            PointSelector::new("first")
                .procedure("guarded")
                .anchor_occurrence(0),
        )
        .bind(
            "second_expression",
            PointSelector::new("second()")
                .procedure("guarded")
                .anchor_occurrence(0),
        )
        .bind(
            "second_normal",
            PointSelector::new("second()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "first_invoke",
            PointSelector::new("first(second())")
                .procedure("guarded")
                .effect("invoke"),
        )
        .bind(
            "first_decision",
            PointSelector::new("first(second())")
                .procedure("guarded")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue)
                .anchor_occurrence(1),
        )
        .bind(
            "first_normal",
            PointSelector::new("first(second())")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "selected_block",
            PointSelector::new(
                r#"{
                        selected();
                    }"#,
            )
            .procedure("guarded")
            .anchor_occurrence(0),
        )
        .bind(
            "after_condition_statement",
            PointSelector::new("after_condition()")
                .procedure("guarded")
                .anchor_occurrence(0),
        )
        .bind(
            "after_condition_full_statement",
            PointSelector::new("after_condition();")
                .procedure("guarded")
                .anchor_occurrence(0),
        );

    graph.assert_successors(
        "nullsafe_decision",
        &[
            cfg_edge("argument_expression", ControlEdgeKind::ConditionalTrue),
            cfg_edge(
                "after_nullsafe_full_statement",
                ControlEdgeKind::ConditionalFalse,
            ),
        ],
    );
    graph.assert_successors(
        "argument_normal",
        &[cfg_edge("nullsafe_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "nullsafe_invoke",
        &[
            cfg_edge("nullsafe_normal", ControlEdgeKind::Normal),
            cfg_edge("nullsafe_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "nullsafe_normal",
        &[cfg_edge(
            "after_nullsafe_full_statement",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_predecessors(
        "after_nullsafe_full_statement",
        &[
            cfg_edge("nullsafe_decision", ControlEdgeKind::ConditionalFalse),
            cfg_edge("nullsafe_normal", ControlEdgeKind::Normal),
        ],
    );
    graph.assert_successors(
        "after_nullsafe_full_statement",
        &[cfg_edge(
            "after_nullsafe_statement",
            ControlEdgeKind::Normal,
        )],
    );

    graph.assert_successors(
        "flag_decision",
        &[
            cfg_edge("right_expression", ControlEdgeKind::ConditionalTrue),
            cfg_edge(
                "after_condition_full_statement",
                ControlEdgeKind::ConditionalFalse,
            ),
        ],
    );
    graph.assert_successors(
        "right_expression",
        &[cfg_edge("first_callee", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "first_callee",
        &[cfg_edge("second_expression", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "second_normal",
        &[cfg_edge("first_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "first_normal",
        &[cfg_edge("first_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "first_decision",
        &[
            cfg_edge("selected_block", ControlEdgeKind::ConditionalTrue),
            cfg_edge(
                "after_condition_full_statement",
                ControlEdgeKind::ConditionalFalse,
            ),
        ],
    );
    graph.assert_successors(
        "after_condition_full_statement",
        &[cfg_edge(
            "after_condition_statement",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_unreachable("first_invoke", "second_expression");
    graph.assert_adjacency_symmetric();
}

#[test]
fn php_nullsafe_dereference_chains_short_circuit_at_the_whole_chain_boundary() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/NullsafeChains.php",
            r#"<?php
                final class ChainService {
                    public function first(): ChainService { return $this; }
                    public function second(int $value): ChainService { return $this; }
                }

                function full_chain(?ChainService $service): void {
                    $service?->first()->second(argument())->{property_name()}[index_value()];
                    after_chain();
                }

                function nested_chain(?ChainService $service): void {
                    $service?->first()?->second(argument());
                    after_nested();
                }

                function property_chain(?ChainService $service): void {
                    $service?->{property_name()};
                    after_property();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/NullsafeChains.php");
    graph
        .bind(
            "full_inner_decision",
            PointSelector::new("$service?->first()")
                .procedure("full_chain")
                .outgoing_kind(ControlEdgeKind::ConditionalFalse),
        )
        .bind(
            "full_inner_invoke",
            PointSelector::new("$service?->first()")
                .procedure("full_chain")
                .effect("invoke"),
        )
        .bind(
            "argument_invoke",
            PointSelector::new("argument()")
                .procedure("full_chain")
                .effect("invoke"),
        )
        .bind(
            "property_name_invoke",
            PointSelector::new("property_name()")
                .procedure("full_chain")
                .effect("invoke"),
        )
        .bind(
            "index_invoke",
            PointSelector::new("index_value()")
                .procedure("full_chain")
                .effect("invoke"),
        )
        .bind(
            "after_chain_statement",
            PointSelector::new("after_chain();")
                .procedure("full_chain")
                .anchor_occurrence(0),
        )
        .bind(
            "nested_inner_decision",
            PointSelector::new("$service?->first()")
                .procedure("nested_chain")
                .outgoing_kind(ControlEdgeKind::ConditionalFalse),
        )
        .bind(
            "nested_inner_invoke",
            PointSelector::new("$service?->first()")
                .procedure("nested_chain")
                .effect("invoke"),
        )
        .bind(
            "nested_outer_decision",
            PointSelector::new("$service?->first()?->second(argument())")
                .procedure("nested_chain")
                .outgoing_kind(ControlEdgeKind::ConditionalFalse),
        )
        .bind(
            "after_nested_statement",
            PointSelector::new("after_nested();")
                .procedure("nested_chain")
                .anchor_occurrence(0),
        )
        .bind(
            "property_decision",
            PointSelector::new("$service?->{property_name()}")
                .procedure("property_chain")
                .outgoing_kind(ControlEdgeKind::ConditionalFalse),
        )
        .bind(
            "property_name_expression",
            PointSelector::new("property_name()")
                .procedure("property_chain")
                .anchor_occurrence(0),
        )
        .bind(
            "after_property_statement",
            PointSelector::new("after_property();")
                .procedure("property_chain")
                .anchor_occurrence(0),
        );

    graph.assert_successors(
        "full_inner_decision",
        &[
            cfg_edge("full_inner_invoke", ControlEdgeKind::ConditionalTrue),
            cfg_edge("after_chain_statement", ControlEdgeKind::ConditionalFalse),
        ],
    );
    for skipped_on_null in ["argument_invoke", "property_name_invoke", "index_invoke"] {
        graph.assert_reachable("full_inner_invoke", skipped_on_null);
        graph.assert_unreachable("after_chain_statement", skipped_on_null);
    }
    graph.assert_successors(
        "nested_inner_decision",
        &[
            cfg_edge("nested_inner_invoke", ControlEdgeKind::ConditionalTrue),
            cfg_edge("after_nested_statement", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_unreachable("after_nested_statement", "nested_outer_decision");
    graph.assert_successors(
        "property_decision",
        &[
            cfg_edge("property_name_expression", ControlEdgeKind::ConditionalTrue),
            cfg_edge(
                "after_property_statement",
                ControlEdgeKind::ConditionalFalse,
            ),
        ],
    );
    graph.assert_unreachable("after_property_statement", "property_name_expression");
    graph.assert_adjacency_symmetric();
}

#[test]
fn php_null_coalescing_tests_nullness_after_evaluating_its_left_expression() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Coalesce.php",
            r#"<?php
                function coalesce(bool $flag): void {
                    ($flag && left_value()) ?? fallback_value();
                    after_coalesce();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/Coalesce.php");
    graph
        .bind(
            "flag_decision",
            PointSelector::new("$flag")
                .occurrence(1)
                .procedure("coalesce")
                .outgoing_kind(ControlEdgeKind::ConditionalFalse),
        )
        .bind(
            "left_call_expression",
            PointSelector::new("left_value()")
                .procedure("coalesce")
                .anchor_occurrence(0),
        )
        .bind(
            "and_merge",
            PointSelector::new("$flag && left_value()")
                .procedure("coalesce")
                .outgoing_kind(ControlEdgeKind::Normal)
                .anchor_occurrence(1),
        )
        .bind(
            "nullish_decision",
            PointSelector::new("($flag && left_value())")
                .procedure("coalesce")
                .outgoing_kind(ControlEdgeKind::ConditionalFalse)
                .anchor_occurrence(0),
        )
        .bind(
            "nonnull_truthiness",
            PointSelector::new("($flag && left_value())")
                .procedure("coalesce")
                .outgoing_kind(ControlEdgeKind::ConditionalFalse)
                .anchor_occurrence(1),
        )
        .bind(
            "fallback_expression",
            PointSelector::new("fallback_value()")
                .procedure("coalesce")
                .anchor_occurrence(0),
        );

    graph.assert_successors(
        "flag_decision",
        &[
            cfg_edge("left_call_expression", ControlEdgeKind::ConditionalTrue),
            cfg_edge("and_merge", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "and_merge",
        &[cfg_edge("nullish_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "nullish_decision",
        &[
            cfg_edge("fallback_expression", ControlEdgeKind::ConditionalFalse),
            cfg_edge("nonnull_truthiness", ControlEdgeKind::ConditionalTrue),
        ],
    );
    graph.assert_adjacency_symmetric();
}

#[test]
fn php_alternative_and_empty_loop_bodies_and_switch_continue_follow_php_control_levels() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/GrammarLoops.php",
            r#"<?php
                function grammar_loops(bool $go, array $items): void {
                    for (; $go;):
                        first_body();
                        second_body();
                        break;
                    endfor;
                    for (; $go;);
                    foreach ($items as $item);
                    after_loops();
                }

                function continue_switch(bool $go): void {
                    while ($go) {
                        switch (1) {
                            default:
                                continue;
                        }
                        after_switch();
                        break;
                    }
                    after_loop();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/GrammarLoops.php");
    graph
        .bind(
            "first_body_normal",
            PointSelector::new("first_body()")
                .procedure("grammar_loops")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "second_body_statement",
            PointSelector::new("second_body();")
                .procedure("grammar_loops")
                .anchor_occurrence(0),
        )
        .bind(
            "second_body_invoke",
            PointSelector::new("second_body()")
                .procedure("grammar_loops")
                .effect("invoke"),
        )
        .bind(
            "alternative_break",
            PointSelector::new("break;")
                .occurrence(0)
                .procedure("grammar_loops")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "empty_for_body",
            PointSelector::new("for (; $go;);")
                .procedure("grammar_loops")
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "empty_for_condition_entry",
            PointSelector::new("$go")
                .occurrence(2)
                .procedure("grammar_loops")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "empty_foreach_body",
            PointSelector::new("foreach ($items as $item);")
                .procedure("grammar_loops")
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "empty_foreach_test",
            PointSelector::new("foreach ($items as $item);")
                .procedure("grammar_loops")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "switch_continue",
            PointSelector::new("continue;")
                .procedure("continue_switch")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "after_switch_statement",
            PointSelector::new("after_switch();")
                .procedure("continue_switch")
                .anchor_occurrence(0),
        );

    graph.assert_successors(
        "first_body_normal",
        &[cfg_edge("second_body_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("second_body_statement", "second_body_invoke");
    graph.assert_reachable("second_body_invoke", "alternative_break");
    graph.assert_successors(
        "switch_continue",
        &[cfg_edge("after_switch_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "empty_for_body",
        &[cfg_edge(
            "empty_for_condition_entry",
            ControlEdgeKind::LoopBack,
        )],
    );
    graph.assert_successors(
        "empty_foreach_body",
        &[cfg_edge("empty_foreach_test", ControlEdgeKind::LoopBack)],
    );
    graph.assert_adjacency_symmetric();
}

#[test]
fn php_static_declare_and_dynamic_class_constant_syntax_retains_runtime_calls_and_gaps() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/DeclarationForms.php",
            r#"<?php
                final class DynamicConstants {
                    public const VALUE = 1;
                }

                function declaration_forms(): void {
                    static $cached = static_initializer();
                    declare(ticks=1):
                        declared_call();
                    enddeclare;
                    (class_name())::VALUE;
                    after_declarations();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/DeclarationForms.php");
    graph
        .bind(
            "static_dispatch",
            PointSelector::new("static $cached = static_initializer();")
                .procedure("declaration_forms")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::ConditionalFalse),
        )
        .bind(
            "static_initializer_expression",
            PointSelector::new("static_initializer()")
                .procedure("declaration_forms")
                .anchor_occurrence(0),
        )
        .bind(
            "declare_entry",
            PointSelector::new("declare(ticks=1):")
                .procedure("declaration_forms")
                .effect("gap"),
        )
        .bind(
            "declared_invoke",
            PointSelector::new("declared_call()")
                .procedure("declaration_forms")
                .effect("invoke"),
        )
        .bind(
            "dynamic_class_invoke",
            PointSelector::new("class_name()")
                .procedure("declaration_forms")
                .effect("invoke"),
        )
        .bind(
            "after_declarations_invoke",
            PointSelector::new("after_declarations()")
                .procedure("declaration_forms")
                .effect("invoke"),
        );

    graph.assert_successors(
        "static_dispatch",
        &[
            cfg_edge(
                "static_initializer_expression",
                ControlEdgeKind::ConditionalTrue,
            ),
            cfg_edge("declare_entry", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_point_gap(
        "static_dispatch",
        SemanticCapability::NormalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "declare_entry",
        SemanticCapability::Calls,
        SemanticGapKind::Unknown,
    );
    graph.assert_reachable("static_initializer_expression", "declared_invoke");
    graph.assert_reachable("declare_entry", "declared_invoke");
    graph.assert_reachable("declared_invoke", "dynamic_class_invoke");
    graph.assert_reachable("dynamic_class_invoke", "after_declarations_invoke");
    graph.assert_adjacency_symmetric();
}

#[test]
fn php_include_continues_with_typed_gaps_while_goto_is_terminal() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/Boundaries.php",
            r#"<?php
                function load_file(string $name): void {
                    include path_for($name);
                    after_include();
                }

                function jump(): void {
                    before_goto();
                    goto Target;
                    dead_after_goto();
                Target:
                    target_body();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/Boundaries.php");
    graph
        .bind(
            "path_normal",
            PointSelector::new("path_for($name)")
                .procedure("load_file")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "include_boundary",
            PointSelector::new("include path_for($name)")
                .procedure("load_file")
                .effect("gap"),
        )
        .bind(
            "after_include_statement",
            PointSelector::new("after_include()")
                .procedure("load_file")
                .anchor_occurrence(0),
        )
        .bind(
            "after_include_full_statement",
            PointSelector::new("after_include();")
                .procedure("load_file")
                .anchor_occurrence(0),
        )
        .bind(
            "after_include_invoke",
            PointSelector::new("after_include()")
                .procedure("load_file")
                .effect("invoke"),
        )
        .bind(
            "jump_entry",
            PointSelector::new("function jump(): void")
                .procedure("jump")
                .effect("entry"),
        )
        .bind(
            "before_goto_normal",
            PointSelector::new("before_goto()")
                .procedure("jump")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "goto_boundary",
            PointSelector::new("goto Target;")
                .procedure("jump")
                .effect("gap"),
        )
        .bind(
            "dead_after_goto",
            PointSelector::new("dead_after_goto()")
                .procedure("jump")
                .effect("invoke"),
        )
        .bind(
            "target_body",
            PointSelector::new("target_body()")
                .procedure("jump")
                .effect("invoke"),
        );

    graph.assert_successors(
        "path_normal",
        &[cfg_edge("include_boundary", ControlEdgeKind::Normal)],
    );
    for (capability, kind) in [
        (SemanticCapability::Calls, SemanticGapKind::Unsupported),
        (
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unsupported,
        ),
        (
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unknown,
        ),
    ] {
        graph.assert_point_gap("include_boundary", capability, kind);
    }
    graph.assert_successors(
        "include_boundary",
        &[cfg_edge(
            "after_include_full_statement",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_successors(
        "after_include_full_statement",
        &[cfg_edge("after_include_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("path_normal", "after_include_invoke");

    graph.assert_successors(
        "before_goto_normal",
        &[cfg_edge("goto_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "goto_boundary",
        SemanticCapability::NonLocalControl,
        SemanticGapKind::Unsupported,
    );
    graph.assert_successors("goto_boundary", &[]);
    graph.assert_reachable("jump_entry", "goto_boundary");
    graph.assert_unreachable("jump_entry", "dead_after_goto");
    graph.assert_unreachable("jump_entry", "target_body");
    graph.assert_adjacency_symmetric();
}

#[test]
fn php_switch_evaluates_predicates_in_order_and_preserves_fallthrough() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/SwitchFlow.php",
            r#"<?php
                function switch_flow(): void {
                    switch (subject()) {
                        case first_case():
                            first_body();
                        default:
                            fallback_body();
                        case second_case():
                            second_body();
                            break;
                    }
                    after_switch();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/SwitchFlow.php");
    let switch_source = r#"switch (subject()) {
                        case first_case():
                            first_body();
                        default:
                            fallback_body();
                        case second_case():
                            second_body();
                            break;
                    }"#;
    let first_case_source = r#"case first_case():
                            first_body();"#;
    let second_case_source = r#"case second_case():
                            second_body();
                            break;"#;
    let default_source = r#"default:
                            fallback_body();"#;
    graph
        .bind(
            "subject_normal",
            PointSelector::new("subject()")
                .procedure("switch_flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "dispatch",
            PointSelector::new(switch_source)
                .procedure("switch_flow")
                .outgoing_kind(ControlEdgeKind::Normal)
                .anchor_occurrence(1),
        )
        .bind(
            "first_predicate_expression",
            PointSelector::new("first_case()")
                .procedure("switch_flow")
                .anchor_occurrence(0),
        )
        .bind(
            "first_predicate_normal",
            PointSelector::new("first_case()")
                .procedure("switch_flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "first_comparison",
            PointSelector::new(first_case_source)
                .procedure("switch_flow")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "first_case_entry",
            PointSelector::new(first_case_source)
                .procedure("switch_flow")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "second_predicate_expression",
            PointSelector::new("second_case()")
                .procedure("switch_flow")
                .anchor_occurrence(0),
        )
        .bind(
            "second_predicate_normal",
            PointSelector::new("second_case()")
                .procedure("switch_flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "second_comparison",
            PointSelector::new(second_case_source)
                .procedure("switch_flow")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "second_case_entry",
            PointSelector::new(second_case_source)
                .procedure("switch_flow")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "default_entry",
            PointSelector::new(default_source)
                .procedure("switch_flow")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "first_body_normal",
            PointSelector::new("first_body()")
                .procedure("switch_flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "fallback_body_normal",
            PointSelector::new("fallback_body()")
                .procedure("switch_flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "break_transfer",
            PointSelector::new("break;")
                .procedure("switch_flow")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "after_switch_statement",
            PointSelector::new("after_switch()")
                .procedure("switch_flow")
                .anchor_occurrence(0),
        )
        .bind(
            "after_switch_full_statement",
            PointSelector::new("after_switch();")
                .procedure("switch_flow")
                .anchor_occurrence(0),
        )
        .bind(
            "after_switch_invoke",
            PointSelector::new("after_switch()")
                .procedure("switch_flow")
                .effect("invoke"),
        );

    graph.assert_successors(
        "subject_normal",
        &[cfg_edge("dispatch", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "dispatch",
        &[cfg_edge(
            "first_predicate_expression",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_successors(
        "first_predicate_normal",
        &[cfg_edge("first_comparison", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "first_comparison",
        &[
            cfg_edge("first_case_entry", ControlEdgeKind::SwitchCase),
            cfg_edge(
                "second_predicate_expression",
                ControlEdgeKind::ConditionalFalse,
            ),
        ],
    );
    graph.assert_successors(
        "second_predicate_normal",
        &[cfg_edge("second_comparison", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "second_comparison",
        &[
            cfg_edge("second_case_entry", ControlEdgeKind::SwitchCase),
            cfg_edge("default_entry", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "first_body_normal",
        &[cfg_edge("default_entry", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "fallback_body_normal",
        &[cfg_edge("second_case_entry", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "break_transfer",
        &[cfg_edge(
            "after_switch_full_statement",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_successors(
        "after_switch_full_statement",
        &[cfg_edge("after_switch_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "first_comparison",
        SemanticCapability::Calls,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "first_comparison",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_reachable("default_entry", "after_switch_invoke");
    graph.assert_adjacency_symmetric();
}

#[test]
fn php_explicit_throw_evaluates_its_value_and_terminates_normal_flow() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/ExplicitThrow.php",
            r#"<?php
                function explicit_throw(): void {
                    before_throw();
                    throw exception_value();
                    dead_after_throw();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/ExplicitThrow.php");
    graph
        .bind(
            "before_throw_normal",
            PointSelector::new("before_throw()")
                .procedure("explicit_throw")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "throw_statement",
            PointSelector::new("throw exception_value();")
                .procedure("explicit_throw")
                .anchor_occurrence(0),
        )
        .bind(
            "exception_value_invoke",
            PointSelector::new("exception_value()")
                .procedure("explicit_throw")
                .effect("invoke"),
        )
        .bind(
            "exception_value_normal",
            PointSelector::new("exception_value()")
                .procedure("explicit_throw")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "throw_transfer",
            PointSelector::new("throw exception_value()")
                .procedure("explicit_throw")
                .effect("throw"),
        )
        .bind(
            "dead_after_throw",
            PointSelector::new("dead_after_throw()")
                .procedure("explicit_throw")
                .effect("invoke"),
        )
        .bind(
            "exceptional_exit",
            PointSelector::new("function explicit_throw(): void")
                .procedure("explicit_throw")
                .effect("exceptional_exit"),
        )
        .bind(
            "normal_exit",
            PointSelector::new("function explicit_throw(): void")
                .procedure("explicit_throw")
                .effect("normal_exit"),
        );

    graph.assert_successors(
        "before_throw_normal",
        &[cfg_edge("throw_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("throw_statement", "exception_value_invoke");
    graph.assert_successors(
        "exception_value_normal",
        &[cfg_edge("throw_transfer", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "throw_transfer",
        &[cfg_edge("exceptional_exit", ControlEdgeKind::Exceptional)],
    );
    graph.assert_unreachable("throw_transfer", "normal_exit");
    graph.assert_unreachable("throw_statement", "dead_after_throw");
    graph.assert_adjacency_symmetric();
}

#[test]
fn php_try_catch_finally_routes_normal_handled_and_unmatched_completion() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/FinallyFlow.php",
            r#"<?php
                function guarded(): void {
                    try {
                        work();
                    } catch (Problem $problem) {
                        handled();
                    } finally {
                        cleanup();
                    }
                    after_try();
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/FinallyFlow.php");
    graph
        .bind(
            "work_normal",
            PointSelector::new("work()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "work_exceptional",
            PointSelector::new("work()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "try_body_exit",
            PointSelector::new(
                r#"{
                        work();
                    }"#,
            )
            .procedure("guarded")
            .outgoing_kind(ControlEdgeKind::Cleanup),
        )
        .bind(
            "handler_dispatch",
            PointSelector::new("try {")
                .procedure("guarded")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "catch_entry",
            PointSelector::new(
                r#"catch (Problem $problem) {
                        handled();
                    }"#,
            )
            .procedure("guarded")
            .outgoing_kind(ControlEdgeKind::Normal)
            .anchor_occurrence(0),
        )
        .bind(
            "unmatched_exception",
            PointSelector::new("try {")
                .procedure("guarded")
                .outgoing_kind(ControlEdgeKind::Cleanup),
        )
        .bind(
            "handled_invoke",
            PointSelector::new("handled()")
                .procedure("guarded")
                .effect("invoke"),
        )
        .bind(
            "handled_normal",
            PointSelector::new("handled()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "catch_body_exit",
            PointSelector::new(
                r#"{
                        handled();
                    }"#,
            )
            .procedure("guarded")
            .outgoing_kind(ControlEdgeKind::Cleanup),
        )
        .bind(
            "normal_cleanup_entry",
            PointSelector::new(
                r#"{
                        cleanup();
                    }"#,
            )
            .procedure("guarded")
            .outgoing_kind(ControlEdgeKind::Normal)
            .anchor_occurrence(2),
        )
        .bind(
            "exceptional_cleanup_entry",
            PointSelector::new(
                r#"{
                        cleanup();
                    }"#,
            )
            .procedure("guarded")
            .outgoing_kind(ControlEdgeKind::Normal)
            .anchor_occurrence(0),
        )
        .bind(
            "normal_cleanup_invoke",
            PointSelector::new("cleanup()")
                .procedure("guarded")
                .effect("invoke")
                .anchor_occurrence(1),
        )
        .bind(
            "normal_cleanup_continuation",
            PointSelector::new("cleanup()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal)
                .anchor_occurrence(2),
        )
        .bind(
            "exceptional_cleanup_invoke",
            PointSelector::new("cleanup()")
                .procedure("guarded")
                .effect("invoke")
                .anchor_occurrence(5),
        )
        .bind(
            "exceptional_cleanup_continuation",
            PointSelector::new("cleanup()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal)
                .anchor_occurrence(6),
        )
        .bind(
            "exceptional_cleanup_relay",
            PointSelector::new(
                r#"{
                        cleanup();
                    }"#,
            )
            .procedure("guarded")
            .outgoing_kind(ControlEdgeKind::Exceptional)
            .anchor_occurrence(1),
        )
        .bind(
            "after_try_statement",
            PointSelector::new("after_try();")
                .procedure("guarded")
                .anchor_occurrence(0),
        )
        .bind(
            "after_try_invoke",
            PointSelector::new("after_try()")
                .procedure("guarded")
                .effect("invoke"),
        )
        .bind(
            "exceptional_exit",
            PointSelector::new("function guarded(): void")
                .procedure("guarded")
                .effect("exceptional_exit"),
        );

    graph.assert_successors(
        "work_normal",
        &[cfg_edge("try_body_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "work_exceptional",
        &[cfg_edge("handler_dispatch", ControlEdgeKind::Exceptional)],
    );
    graph.assert_point_gap(
        "handler_dispatch",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_successors(
        "handler_dispatch",
        &[
            cfg_edge("catch_entry", ControlEdgeKind::SwitchCase),
            cfg_edge("unmatched_exception", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_reachable("catch_entry", "handled_invoke");
    graph.assert_successors(
        "handled_normal",
        &[cfg_edge("catch_body_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "try_body_exit",
        &[cfg_edge("normal_cleanup_entry", ControlEdgeKind::Cleanup)],
    );
    graph.assert_successors(
        "catch_body_exit",
        &[cfg_edge("normal_cleanup_entry", ControlEdgeKind::Cleanup)],
    );
    graph.assert_predecessors(
        "normal_cleanup_entry",
        &[
            cfg_edge("try_body_exit", ControlEdgeKind::Cleanup),
            cfg_edge("catch_body_exit", ControlEdgeKind::Cleanup),
        ],
    );
    graph.assert_successors(
        "unmatched_exception",
        &[cfg_edge(
            "exceptional_cleanup_entry",
            ControlEdgeKind::Cleanup,
        )],
    );
    graph.assert_reachable("normal_cleanup_entry", "normal_cleanup_invoke");
    graph.assert_successors(
        "normal_cleanup_continuation",
        &[cfg_edge("after_try_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("exceptional_cleanup_entry", "exceptional_cleanup_invoke");
    graph.assert_successors(
        "exceptional_cleanup_continuation",
        &[cfg_edge(
            "exceptional_cleanup_relay",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_successors(
        "exceptional_cleanup_relay",
        &[cfg_edge("exceptional_exit", ControlEdgeKind::Exceptional)],
    );
    graph.assert_reachable("normal_cleanup_entry", "after_try_statement");
    graph.assert_reachable("normal_cleanup_entry", "after_try_invoke");
    graph.assert_unreachable("unmatched_exception", "after_try_invoke");
    graph.assert_reachable("unmatched_exception", "exceptional_exit");
    graph.assert_adjacency_symmetric();
}

#[test]
fn php_match_selected_values_merge_after_ordered_predicates() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/MatchFlow.php",
            r#"<?php
                function match_flow(): void {
                    $chosen = match (match_subject()) {
                        first_key() => first_value(),
                        second_key() => second_value(),
                        default => fallback_value(),
                    };
                    after_match($chosen);
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/MatchFlow.php");
    let match_source = r#"match (match_subject()) {
                        first_key() => first_value(),
                        second_key() => second_value(),
                        default => fallback_value(),
                    }"#;
    graph
        .bind(
            "subject_normal",
            PointSelector::new("match_subject()")
                .procedure("match_flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "first_predicate_expression",
            PointSelector::new("first_key()")
                .procedure("match_flow")
                .anchor_occurrence(0),
        )
        .bind(
            "first_predicate_normal",
            PointSelector::new("first_key()")
                .procedure("match_flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "first_comparison",
            PointSelector::new("first_key()")
                .procedure("match_flow")
                .outgoing_kind(ControlEdgeKind::SwitchCase)
                .anchor_occurrence(1),
        )
        .bind(
            "second_predicate_expression",
            PointSelector::new("second_key()")
                .procedure("match_flow")
                .anchor_occurrence(0),
        )
        .bind(
            "second_predicate_normal",
            PointSelector::new("second_key()")
                .procedure("match_flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "second_comparison",
            PointSelector::new("second_key()")
                .procedure("match_flow")
                .outgoing_kind(ControlEdgeKind::SwitchCase)
                .anchor_occurrence(1),
        )
        .bind(
            "first_value_entry",
            PointSelector::new("first_value()")
                .procedure("match_flow")
                .anchor_occurrence(0),
        )
        .bind(
            "first_value_normal",
            PointSelector::new("first_value()")
                .procedure("match_flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "second_value_entry",
            PointSelector::new("second_value()")
                .procedure("match_flow")
                .anchor_occurrence(0),
        )
        .bind(
            "second_value_normal",
            PointSelector::new("second_value()")
                .procedure("match_flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "fallback_value_entry",
            PointSelector::new("fallback_value()")
                .procedure("match_flow")
                .anchor_occurrence(0),
        )
        .bind(
            "fallback_value_normal",
            PointSelector::new("fallback_value()")
                .procedure("match_flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "match_merge",
            PointSelector::new(match_source)
                .procedure("match_flow")
                .outgoing_kind(ControlEdgeKind::Normal)
                .anchor_occurrence(1),
        )
        .bind(
            "assignment_boundary",
            PointSelector::new("$chosen = match")
                .procedure("match_flow")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "after_match_statement",
            PointSelector::new("after_match($chosen)")
                .procedure("match_flow")
                .anchor_occurrence(0),
        )
        .bind(
            "after_match_full_statement",
            PointSelector::new("after_match($chosen);")
                .procedure("match_flow")
                .anchor_occurrence(0),
        );

    graph.assert_successors(
        "subject_normal",
        &[cfg_edge(
            "first_predicate_expression",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_successors(
        "first_predicate_normal",
        &[cfg_edge("first_comparison", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "first_comparison",
        &[
            cfg_edge("first_value_entry", ControlEdgeKind::SwitchCase),
            cfg_edge(
                "second_predicate_expression",
                ControlEdgeKind::ConditionalFalse,
            ),
        ],
    );
    graph.assert_successors(
        "second_predicate_normal",
        &[cfg_edge("second_comparison", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "second_comparison",
        &[
            cfg_edge("second_value_entry", ControlEdgeKind::SwitchCase),
            cfg_edge("fallback_value_entry", ControlEdgeKind::ConditionalFalse),
        ],
    );
    for result in [
        "first_value_normal",
        "second_value_normal",
        "fallback_value_normal",
    ] {
        graph.assert_successors(result, &[cfg_edge("match_merge", ControlEdgeKind::Normal)]);
    }
    graph.assert_predecessors(
        "match_merge",
        &[
            cfg_edge("first_value_normal", ControlEdgeKind::Normal),
            cfg_edge("second_value_normal", ControlEdgeKind::Normal),
            cfg_edge("fallback_value_normal", ControlEdgeKind::Normal),
        ],
    );
    graph.assert_unreachable("first_value_normal", "second_value_entry");
    graph.assert_unreachable("second_value_normal", "first_value_entry");
    graph.assert_successors(
        "match_merge",
        &[cfg_edge("assignment_boundary", ControlEdgeKind::Normal)],
    );
    for capability in [
        SemanticCapability::NormalControlFlow,
        SemanticCapability::Calls,
        SemanticCapability::ExceptionalControlFlow,
    ] {
        graph.assert_point_gap("assignment_boundary", capability, SemanticGapKind::Unknown);
    }
    graph.assert_successors(
        "assignment_boundary",
        &[cfg_edge(
            "after_match_full_statement",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_successors(
        "after_match_full_statement",
        &[cfg_edge("after_match_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_adjacency_symmetric();
}

#[test]
fn php_match_without_default_has_an_explicit_exceptional_completion() {
    let project = InlineTestProject::with_language(Language::Php)
        .file(
            "src/IncompleteMatch.php",
            r#"<?php
                function incomplete_match(): int {
                    return match (missing_subject()) {
                        1 => chosen_value(),
                    };
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "src/IncompleteMatch.php");
    let match_source = r#"match (missing_subject()) {
                        1 => chosen_value(),
                    }"#;
    graph
        .bind(
            "subject_normal",
            PointSelector::new("missing_subject()")
                .procedure("incomplete_match")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "predicate_entry",
            PointSelector::new("1")
                .procedure("incomplete_match")
                .anchor_occurrence(0),
        )
        .bind(
            "comparison",
            PointSelector::new("1")
                .procedure("incomplete_match")
                .outgoing_kind(ControlEdgeKind::SwitchCase)
                .anchor_occurrence(1),
        )
        .bind(
            "chosen_entry",
            PointSelector::new("chosen_value()")
                .procedure("incomplete_match")
                .anchor_occurrence(0),
        )
        .bind(
            "chosen_normal",
            PointSelector::new("chosen_value()")
                .procedure("incomplete_match")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "match_merge",
            PointSelector::new(match_source)
                .procedure("incomplete_match")
                .outgoing_kind(ControlEdgeKind::Normal)
                .anchor_occurrence(1),
        )
        .bind(
            "unmatched_throw",
            PointSelector::new(match_source)
                .procedure("incomplete_match")
                .effect("throw"),
        )
        .bind(
            "return",
            PointSelector::new("return match")
                .procedure("incomplete_match")
                .effect("procedure_return"),
        )
        .bind(
            "normal_exit",
            PointSelector::new("function incomplete_match(): int")
                .procedure("incomplete_match")
                .effect("normal_exit"),
        )
        .bind(
            "exceptional_exit",
            PointSelector::new("function incomplete_match(): int")
                .procedure("incomplete_match")
                .effect("exceptional_exit"),
        );

    graph.assert_successors(
        "subject_normal",
        &[cfg_edge("predicate_entry", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "comparison",
        &[
            cfg_edge("chosen_entry", ControlEdgeKind::SwitchCase),
            cfg_edge("unmatched_throw", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "chosen_normal",
        &[cfg_edge("match_merge", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "match_merge",
        &[cfg_edge("return", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "return",
        &[cfg_edge("normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "unmatched_throw",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_successors(
        "unmatched_throw",
        &[cfg_edge("exceptional_exit", ControlEdgeKind::Exceptional)],
    );
    graph.assert_unreachable("unmatched_throw", "normal_exit");
    graph.assert_adjacency_symmetric();
}
