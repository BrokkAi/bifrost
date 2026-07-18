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
