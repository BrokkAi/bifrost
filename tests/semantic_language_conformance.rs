mod common;

use brokk_bifrost::analyzer::semantic::{
    ControlEdgeKind, DeclarationSegmentKind, IcfgEdgeKind, ProcedureKind, SemanticCapability,
    SemanticGapKind, SemanticLanguage,
};
use brokk_bifrost::{AnalyzerConfig, Language};

use common::{
    InlineTestProject,
    semantic_graph::{
        CallContextSelector, IcfgGraph, IcfgOutcomeKind, PointSelector, SemanticGraph,
        edge as cfg_edge, icfg_edge,
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
    graph.assert_successors("yield_gap", &[]);
    graph.assert_adjacency_symmetric();

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
