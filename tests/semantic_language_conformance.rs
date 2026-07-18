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
