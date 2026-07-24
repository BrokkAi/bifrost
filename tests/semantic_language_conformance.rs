mod common;

use brokk_bifrost::analyzer::semantic::{
    CallableReferenceKind, CallableTargetResolution, CancellationToken, ControlEdgeKind,
    DeclarationSegmentKind, DeferredInvocationKind, IcfgEdgeKind, ProcedureInvocationKind,
    ProcedureKind, ProcedureSemantics, SemanticBudget, SemanticBudgetDimension, SemanticCallSite,
    SemanticCapability, SemanticEffect, SemanticGap, SemanticGapImpact, SemanticGapKind,
    SemanticGapSubject, SemanticLanguage, SemanticOutcome, SemanticRequest,
};
use brokk_bifrost::{AnalyzerConfig, Language};

use common::{
    BuiltInlineTestProject, InlineTestProject,
    semantic_graph::{
        CallContextSelector, ExpectedIcfgBoundary, ExpectedIcfgBoundaryKind, IcfgGraph,
        IcfgOutcomeKind, PointSelector, SemanticGraph, edge as cfg_edge, icfg_edge,
        procedure_source,
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

fn procedure_named<'artifact>(
    graph: &'artifact SemanticGraph,
    name: &str,
    kind: ProcedureKind,
) -> &'artifact ProcedureSemantics {
    graph
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
        .unwrap_or_else(|| panic!("missing {kind:?} procedure {name}"))
}

fn call_site_source<'source>(
    procedure: &ProcedureSemantics,
    source: &'source str,
    call: &SemanticCallSite,
) -> &'source str {
    let span = procedure
        .source_mapping(call.source)
        .expect("semantic call site must retain a source mapping")
        .locator
        .anchor()
        .span();
    source
        .get(span.start_byte() as usize..span.end_byte() as usize)
        .expect("semantic call-site source span must index the fixture")
}

fn exact_call_site<'procedure>(
    procedure: &'procedure ProcedureSemantics,
    source: &str,
    expected_source: &str,
) -> &'procedure SemanticCallSite {
    procedure
        .call_sites()
        .iter()
        .find(|call| call_site_source(procedure, source, call) == expected_source)
        .unwrap_or_else(|| panic!("missing semantic call site for {expected_source:?}"))
}

fn assert_no_exact_call_site(
    procedure: &ProcedureSemantics,
    source: &str,
    unexpected_source: &str,
) {
    assert!(
        procedure
            .call_sites()
            .iter()
            .all(|call| call_site_source(procedure, source, call) != unexpected_source),
        "unexpected eager semantic call site for {unexpected_source:?}"
    );
}

fn assert_call_site_gap(
    procedure: &ProcedureSemantics,
    source: &str,
    call_source: &str,
    capability: SemanticCapability,
    kind: SemanticGapKind,
) {
    let call = exact_call_site(procedure, source, call_source);
    let point = procedure
        .point(call.point)
        .expect("semantic call site must own a program point");
    assert!(
        point.events.iter().any(|event| {
            let SemanticEffect::Gap { gap } = &event.effect else {
                return false;
            };
            procedure.gap(*gap).is_some_and(|gap| {
                gap.point == call.point
                    && gap.subject == SemanticGapSubject::CallSite(call.id)
                    && gap.capability == capability
                    && gap.kind == kind
            })
        }),
        "missing CallSite-scoped {capability:?}:{kind:?} gap for {call_source:?}"
    );
}

fn assert_procedure_gap(
    procedure: &ProcedureSemantics,
    capability: SemanticCapability,
    kind: SemanticGapKind,
) {
    assert!(
        procedure.gaps().iter().any(|gap| {
            gap.subject == SemanticGapSubject::Procedure
                && gap.capability == capability
                && gap.kind == kind
        }),
        "missing Procedure-scoped {capability:?}:{kind:?} gap for {:?}",
        procedure.locator().declaration()
    );
}

fn assert_source_point_gap(
    procedure: &ProcedureSemantics,
    source: &str,
    expected_source: &str,
    capability: SemanticCapability,
    kind: SemanticGapKind,
) {
    assert!(
        procedure.points().iter().any(|point| {
            let Some(mapping) = procedure.source_mapping(point.source) else {
                return false;
            };
            let span = mapping.locator.anchor().span();
            if source.get(span.start_byte() as usize..span.end_byte() as usize)
                != Some(expected_source)
            {
                return false;
            }
            point.events.iter().any(|event| {
                let SemanticEffect::Gap { gap } = &event.effect else {
                    return false;
                };
                procedure.gap(*gap).is_some_and(|gap| {
                    gap.point == point.id
                        && gap.subject == SemanticGapSubject::Point
                        && gap.capability == capability
                        && gap.kind == kind
                })
            })
        }),
        "missing exact source-backed Point-scoped {capability:?}:{kind:?} gap for {expected_source:?}"
    );
}

fn assert_deferred_effect_impacts(gap: &SemanticGap, weakens_call_evaluation: bool, context: &str) {
    assert_eq!(gap.capability, SemanticCapability::DeferredExecution);
    for impact in [
        SemanticGapImpact::ReturnTransfer,
        SemanticGapImpact::ValueFlow,
        SemanticGapImpact::HeapRead,
        SemanticGapImpact::HeapWrite,
        SemanticGapImpact::Aliasing,
    ] {
        assert!(
            gap.impacts.contains(impact),
            "DeferredExecution at {context} must surface {impact:?} uncertainty",
        );
    }
    assert_eq!(
        gap.impacts.contains(SemanticGapImpact::CallEvaluation),
        weakens_call_evaluation,
        "DeferredExecution impact must reflect whether {context} leaves a represented caller-side transfer incomplete",
    );
    assert!(!gap.impacts.contains(SemanticGapImpact::DispatchCoverage));
}

fn assert_direct_call_conformance(fixture: DirectCallFixture) {
    let project = InlineTestProject::with_language(fixture.language)
        .file(fixture.callee_path, fixture.callee_source)
        .file(fixture.caller_path, fixture.caller_source)
        .build();
    assert_direct_call_project_conformance(&project, fixture, DirectCallExpectations::default());
}

fn assert_closed_dispatch_direct_call_conformance(fixture: DirectCallFixture) {
    let project = InlineTestProject::with_language(fixture.language)
        .file(fixture.callee_path, fixture.callee_source)
        .file(fixture.caller_path, fixture.caller_source)
        .build();
    assert_direct_call_project_conformance(
        &project,
        fixture,
        DirectCallExpectations {
            closed_dispatch_refinement: true,
            ..DirectCallExpectations::default()
        },
    );
}

fn assert_return_partial_direct_call_conformance(fixture: DirectCallFixture) {
    let project = InlineTestProject::with_language(fixture.language)
        .file(fixture.callee_path, fixture.callee_source)
        .file(fixture.caller_path, fixture.caller_source)
        .build();
    assert_direct_call_project_conformance(
        &project,
        fixture,
        DirectCallExpectations {
            unproven_return: true,
            ..DirectCallExpectations::default()
        },
    );
}

fn assert_closed_dispatch_return_partial_direct_call_conformance(fixture: DirectCallFixture) {
    let project = InlineTestProject::with_language(fixture.language)
        .file(fixture.callee_path, fixture.callee_source)
        .file(fixture.caller_path, fixture.caller_source)
        .build();
    assert_direct_call_project_conformance(
        &project,
        fixture,
        DirectCallExpectations {
            unproven_return: true,
            closed_dispatch_refinement: true,
            ..DirectCallExpectations::default()
        },
    );
}

#[derive(Debug, Default, Clone, Copy)]
struct DirectCallExpectations {
    unproven_link_unit: bool,
    unproven_return: bool,
    closed_dispatch_refinement: bool,
}

fn assert_direct_call_project_conformance(
    project: &BuiltInlineTestProject,
    fixture: DirectCallFixture,
    expectations: DirectCallExpectations,
) {
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut cfg = SemanticGraph::materialize(project, &analyzer, fixture.caller_path);

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

    assert!(
        cfg.artifact()
            .capabilities()
            .is_available(SemanticCapability::DynamicDispatch),
        "{:?} must publish its dynamic-dispatch capability",
        fixture.language
    );
    let caller = cfg
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
                == Some(fixture.caller_name)
        })
        .expect("direct-call caller procedure");
    let direct_call = exact_call_site(caller, fixture.caller_source, fixture.call);
    let has_dynamic_dispatch_gap = caller.gaps().iter().any(|gap| {
        gap.point == direct_call.point
            && gap.capability == SemanticCapability::DynamicDispatch
            && (gap.subject == SemanticGapSubject::Point
                || gap.subject == SemanticGapSubject::CallSite(direct_call.id))
    });
    let has_unresolved_dynamic_dispatch =
        has_dynamic_dispatch_gap && !expectations.closed_dispatch_refinement;

    let mut icfg = IcfgGraph::materialize(
        project,
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

    if has_unresolved_dynamic_dispatch
        || expectations.unproven_link_unit
        || expectations.unproven_return
    {
        icfg.assert_outcome(IcfgOutcomeKind::Unproven);
    } else {
        icfg.assert_outcome(IcfgOutcomeKind::Complete);
    }
    if has_unresolved_dynamic_dispatch || expectations.unproven_link_unit {
        icfg.assert_boundary(
            "icfg_invoke",
            ExpectedIcfgBoundary::new(ExpectedIcfgBoundaryKind::DispatchUnresolved)
                .originating_call("direct_call"),
        );
    }
    icfg.assert_successors(
        "icfg_invoke",
        &[icfg_edge("callee_entry", IcfgEdgeKind::Call).originating_call("direct_call")],
    );
    icfg.assert_predecessors(
        "callee_entry",
        &[icfg_edge("icfg_invoke", IcfgEdgeKind::Call).originating_call("direct_call")],
    );
    let return_edge = icfg_edge("icfg_normal_continuation", IcfgEdgeKind::NormalReturn)
        .originating_call("direct_call");
    icfg.assert_successors("callee_normal_exit", &[return_edge]);
    if expectations.unproven_link_unit || expectations.unproven_return {
        icfg.assert_edge_unproven_partial("callee_normal_exit", return_edge);
    } else {
        // An open target set weakens the operation and adds an unresolved arm,
        // but it does not invalidate proof for a retained exact candidate.
        icfg.assert_edge_proven_complete("callee_normal_exit", return_edge);
    }
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
fn receiver_calls_publish_point_specific_dynamic_dispatch_gaps() {
    let fixtures = [
        (
            "dispatch/Member.java",
            r#"class Member {
    int run() { return 1; }
    int caller(Member receiver) { return receiver.run(); }
}
"#,
            "caller",
            "receiver.run()",
        ),
        (
            "dispatch/member.go",
            r#"package dispatch
type Member struct{}
func (Member) Run() int { return 1 }
func caller(receiver Member) int { return receiver.Run() }
"#,
            "caller",
            "receiver.Run()",
        ),
        (
            "dispatch/member.js",
            r#"export function caller(receiver) {
    return receiver.run();
}
"#,
            "caller",
            "receiver.run()",
        ),
        (
            "dispatch/member.ts",
            r#"export function caller(receiver: { run(): number }): number {
    return receiver.run();
}
"#,
            "caller",
            "receiver.run()",
        ),
        (
            "dispatch/member.py",
            r#"def caller(receiver):
    return receiver.run()
"#,
            "caller",
            "receiver.run()",
        ),
        (
            "dispatch/member.rs",
            r#"struct Member;
impl Member { fn run(&self) -> i32 { 1 } }
fn caller(receiver: Member) -> i32 { receiver.run() }
"#,
            "caller",
            "receiver.run()",
        ),
        (
            "dispatch/member.php",
            r#"<?php
function caller($receiver) {
    return $receiver->run();
}
"#,
            "caller",
            "$receiver->run()",
        ),
        (
            "dispatch/Member.scala",
            r#"class Member { def run(): Int = 1 }
def caller(receiver: Member): Int = receiver.run()
"#,
            "caller",
            "receiver.run()",
        ),
        (
            "dispatch/Member.cs",
            r#"class Member {
    int Run() => 1;
    static int Caller(Member receiver) => receiver.Run();
}
"#,
            "Caller",
            "receiver.Run()",
        ),
        (
            "dispatch/member.rb",
            r#"def caller(receiver)
  receiver.run
end
"#,
            "caller",
            "receiver.run",
        ),
    ];
    let mut project_builder = InlineTestProject::new();
    for (path, source, _, _) in fixtures {
        project_builder = project_builder.file(path, source);
    }
    let project = project_builder.build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());

    for (path, source, procedure_name, call_source) in fixtures {
        let graph = SemanticGraph::materialize(&project, &analyzer, path);
        assert!(
            graph
                .artifact()
                .capabilities()
                .is_available(SemanticCapability::DynamicDispatch),
            "{path} must publish dynamic-dispatch support"
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
                    == Some(procedure_name)
            })
            .unwrap_or_else(|| panic!("missing {procedure_name} in {path}"));
        assert_call_site_gap(
            procedure,
            source,
            call_source,
            SemanticCapability::DynamicDispatch,
            SemanticGapKind::Unknown,
        );
    }
}

fn assert_declared_cpp_direct_call_conformance(
    header_path: &'static str,
    header_source: &'static str,
    fixture: DirectCallFixture,
) {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(header_path, header_source)
        .file(fixture.callee_path, fixture.callee_source)
        .file(fixture.caller_path, fixture.caller_source)
        .build();
    assert_direct_call_project_conformance(
        &project,
        fixture,
        DirectCallExpectations {
            unproven_link_unit: true,
            ..DirectCallExpectations::default()
        },
    );
}

#[test]
fn java_direct_call_conformance() {
    assert_closed_dispatch_direct_call_conformance(DirectCallFixture {
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
fn scala_direct_call_conformance() {
    assert_closed_dispatch_direct_call_conformance(DirectCallFixture {
        language: Language::Scala,
        dialect: SemanticLanguage::Standard(Language::Scala),
        callee_path: "scala/conformance/ScalaLibrary.scala",
        callee_source: r#"
            package conformance

            object ScalaLibrary {
              def scalaLeaf(): Int = 7
            }
        "#,
        callee_declaration: "def scalaLeaf(): Int",
        callee_name: "scalaLeaf",
        caller_path: "scala/conformance/ScalaCaller.scala",
        caller_source: r#"
            package conformance

            object ScalaCaller {
              def scalaRoot(): Int = ScalaLibrary.scalaLeaf()
            }
        "#,
        caller_declaration: "def scalaRoot(): Int",
        caller_name: "scalaRoot",
        call: "ScalaLibrary.scalaLeaf()",
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
fn c_direct_free_call_coalesces_header_declaration_with_definition() {
    assert_declared_cpp_direct_call_conformance(
        "c/conformance/library.h",
        "int c_leaf(int value);\n",
        DirectCallFixture {
            language: Language::Cpp,
            dialect: SemanticLanguage::Standard(Language::Cpp),
            callee_path: "c/conformance/library.c",
            callee_source: r#"#include "library.h"

int c_leaf(int value) {
    return value + 1;
}
"#,
            callee_declaration: "int c_leaf(int value)",
            callee_name: "c_leaf",
            caller_path: "c/conformance/caller.c",
            caller_source: r#"#include "library.h"

int c_root(int value) {
    return c_leaf(value);
}
"#,
            caller_declaration: "int c_root(int value)",
            caller_name: "c_root",
            call: "c_leaf(value)",
        },
    );
}

#[test]
fn cpp_direct_free_call_coalesces_header_declaration_with_definition() {
    assert_declared_cpp_direct_call_conformance(
        "cpp/conformance/library.hpp",
        "int cpp_leaf(int value);\n",
        DirectCallFixture {
            language: Language::Cpp,
            dialect: SemanticLanguage::Standard(Language::Cpp),
            callee_path: "cpp/conformance/library.cpp",
            callee_source: r#"#include "library.hpp"

int cpp_leaf(int value) {
    return value + 1;
}
"#,
            callee_declaration: "int cpp_leaf(int value)",
            callee_name: "cpp_leaf",
            caller_path: "cpp/conformance/caller.cpp",
            caller_source: r#"#include "library.hpp"

int cpp_root(int value) {
    return cpp_leaf(value);
}
"#,
            caller_declaration: "int cpp_root(int value)",
            caller_name: "cpp_root",
            call: "cpp_leaf(value)",
        },
    );
}

#[test]
fn rust_turbofish_direct_call_uses_the_shared_dispatch_oracle() {
    assert_closed_dispatch_direct_call_conformance(DirectCallFixture {
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
    assert_closed_dispatch_return_partial_direct_call_conformance(DirectCallFixture {
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
    let source = r#"
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
            "#;
    let project = InlineTestProject::with_language(Language::Rust)
        .file("rust/implicit_calls.rs", source)
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
    let procedure = procedure_named(&graph, "implicit_operations", ProcedureKind::Function);
    let method_call = exact_call_site(procedure, source, "holder.method()");
    let receiver_adjustment_gap = procedure
        .gaps()
        .iter()
        .find(|gap| {
            gap.point == method_call.point
                && gap.subject == SemanticGapSubject::Point
                && gap.capability == SemanticCapability::Calls
        })
        .expect("method call must retain its receiver-adjustment gap");
    assert!(
        receiver_adjustment_gap
            .impacts
            .contains(SemanticGapImpact::CallEvaluation),
        "omitted Deref/DerefMut calls must weaken caller-side evaluation",
    );
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
            PointSelector::new(
                r#"{
                        let guard = acquire();
                        use_guard(&guard);
                    }"#,
            )
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
fn c_branches_loops_abrupt_flow_and_calls_have_exact_topology() {
    let project = InlineTestProject::with_language(Language::Cpp)
        .file(
            "c/common_control.c",
            r#"void c_tick(int value);
void c_done(void);
void c_dead(void);

void c_flow(int value) {
    if (value < 0) {
        return;
        c_dead();
    }
    while (value > 0) {
        if (value == 3) {
            --value;
            continue;
        }
        if (value == 1) {
            break;
        }
        c_tick(value);
        --value;
    }
    c_done();
}
"#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "c/common_control.c");
    graph
        .bind(
            "entry",
            PointSelector::new("void c_flow(int value)")
                .procedure("c_flow")
                .effect("entry"),
        )
        .bind(
            "early_return",
            PointSelector::new("return;")
                .procedure("c_flow")
                .effect("procedure_return"),
        )
        .bind(
            "dead_invoke",
            PointSelector::new("c_dead()")
                .procedure("c_flow")
                .effect("invoke"),
        )
        .bind(
            "loop_condition",
            PointSelector::new("value > 0")
                .procedure("c_flow")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "continue",
            PointSelector::new("continue;")
                .procedure("c_flow")
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "break",
            PointSelector::new("break;")
                .procedure("c_flow")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "tick_invoke",
            PointSelector::new("c_tick(value)")
                .procedure("c_flow")
                .effect("invoke"),
        )
        .bind(
            "tick_normal",
            PointSelector::new("c_tick(value)")
                .procedure("c_flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "tick_exceptional",
            PointSelector::new("c_tick(value)")
                .procedure("c_flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "decrement_after_tick",
            PointSelector::new("--value;")
                .occurrence(1)
                .procedure("c_flow")
                .anchor_occurrence(0),
        )
        .bind(
            "done_invoke",
            PointSelector::new("c_done()")
                .procedure("c_flow")
                .effect("invoke"),
        )
        .bind(
            "done_normal",
            PointSelector::new("c_done()")
                .procedure("c_flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "normal_exit",
            PointSelector::new("void c_flow(int value)")
                .procedure("c_flow")
                .effect("normal_exit"),
        )
        .bind(
            "exceptional_exit",
            PointSelector::new("void c_flow(int value)")
                .procedure("c_flow")
                .effect("exceptional_exit"),
        );

    graph.assert_successors(
        "early_return",
        &[cfg_edge("normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "tick_invoke",
        &[
            cfg_edge("tick_normal", ControlEdgeKind::Normal),
            cfg_edge("tick_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_predecessors(
        "tick_normal",
        &[cfg_edge("tick_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "tick_normal",
        &[cfg_edge("decrement_after_tick", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "tick_exceptional",
        &[cfg_edge("exceptional_exit", ControlEdgeKind::Exceptional)],
    );
    graph.assert_successors(
        "done_normal",
        &[cfg_edge("normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("entry", "loop_condition");
    graph.assert_reachable("entry", "continue");
    graph.assert_reachable("continue", "done_invoke");
    graph.assert_reachable("entry", "break");
    graph.assert_reachable("break", "done_invoke");
    graph.assert_reachable("entry", "done_invoke");
    graph.assert_unreachable("entry", "dead_invoke");
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn cpp_nested_lambda_is_a_separate_immediate_procedure() {
    let source = r#"int cpp_leaf(int value);

int cpp_outer(bool take_branch) {
    auto nested = [take_branch]() {
        return cpp_leaf(1);
    };
    if (take_branch) {
        return cpp_leaf(2);
    }
    return 0;
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("cpp/nested_lambda.cpp", source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "cpp/nested_lambda.cpp");
    graph
        .bind(
            "outer_entry",
            PointSelector::new("int cpp_outer(bool take_branch)")
                .procedure("cpp_outer")
                .effect("entry"),
        )
        .bind(
            "outer_invoke",
            PointSelector::new("cpp_leaf(2)")
                .procedure("cpp_outer")
                .effect("invoke"),
        )
        .bind(
            "outer_normal",
            PointSelector::new("cpp_leaf(2)")
                .procedure("cpp_outer")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "outer_exceptional",
            PointSelector::new("cpp_leaf(2)")
                .procedure("cpp_outer")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "lambda_entry",
            PointSelector::new("[take_branch]()")
                .procedure("nested")
                .effect("entry"),
        )
        .bind(
            "lambda_invoke",
            PointSelector::new("cpp_leaf(1)")
                .procedure("nested")
                .effect("invoke"),
        )
        .bind(
            "lambda_normal",
            PointSelector::new("cpp_leaf(1)")
                .procedure("nested")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "lambda_return",
            PointSelector::new("return cpp_leaf(1);")
                .procedure("nested")
                .effect("procedure_return"),
        );

    let outer = procedure_named(&graph, "cpp_outer", ProcedureKind::Function);
    let lambda = procedure_named(&graph, "nested", ProcedureKind::Lambda);
    assert_eq!(lambda.lexical_parent(), Some(outer.id()));
    assert_eq!(
        lambda.properties().invocation,
        ProcedureInvocationKind::Immediate
    );
    assert_no_exact_call_site(outer, source, "cpp_leaf(1)");
    assert_eq!(
        call_site_source(
            lambda,
            source,
            exact_call_site(lambda, source, "cpp_leaf(1)")
        ),
        "cpp_leaf(1)"
    );
    graph.assert_successors(
        "outer_invoke",
        &[
            cfg_edge("outer_normal", ControlEdgeKind::Normal),
            cfg_edge("outer_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "lambda_normal",
        &[cfg_edge("lambda_return", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("outer_entry", "outer_invoke");
    graph.assert_reachable("lambda_entry", "lambda_invoke");
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn cpp_switch_fallthrough_goto_and_try_have_exact_topology() {
    let switch_source = r#"switch (tag) {
    case 0:
        cpp_first();
    case 1:
        cpp_second();
        break;
    default:
        cpp_fallback();
    }"#;
    let try_source = r#"try {
        if (fail) {
            throw 7;
            cpp_dead_throw();
        }
        cpp_normal();
    } catch (int value) {
        cpp_handled();
    }"#;
    let catch_source = r#"catch (int value) {
        cpp_handled();
    }"#;
    let source = format!(
        r#"struct JumpGuard {{}};

void cpp_first();
void cpp_second();
void cpp_fallback();
void cpp_after_switch();
void cpp_dead();
void cpp_live();
void cpp_done();
void cpp_dead_throw();
void cpp_normal();
void cpp_handled();
void cpp_after_try();

void cpp_switch(int tag) {{
    {switch_source}
    cpp_after_switch();
}}

void cpp_jump(bool repeat) {{
    JumpGuard guard;
    goto cpp_target;
    cpp_dead();
cpp_target:
    cpp_live();
    if (repeat) {{
        goto cpp_target;
    }}
    cpp_done();
}}

void cpp_try(bool fail) {{
    {try_source}
    cpp_after_try();
}}
"#
    );
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("cpp/nonlocal_control.cpp", &source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "cpp/nonlocal_control.cpp");
    graph
        .bind(
            "switch_dispatch",
            PointSelector::new(switch_source)
                .procedure("cpp_switch")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "first_invoke",
            PointSelector::new("cpp_first()")
                .procedure("cpp_switch")
                .effect("invoke"),
        )
        .bind(
            "first_normal",
            PointSelector::new("cpp_first()")
                .procedure("cpp_switch")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "second_invoke",
            PointSelector::new("cpp_second()")
                .procedure("cpp_switch")
                .effect("invoke"),
        )
        .bind(
            "second_normal",
            PointSelector::new("cpp_second()")
                .procedure("cpp_switch")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "switch_break",
            PointSelector::new("break;")
                .procedure("cpp_switch")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "fallback_invoke",
            PointSelector::new("cpp_fallback()")
                .procedure("cpp_switch")
                .effect("invoke"),
        )
        .bind(
            "fallback_normal",
            PointSelector::new("cpp_fallback()")
                .procedure("cpp_switch")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "after_switch_invoke",
            PointSelector::new("cpp_after_switch()")
                .procedure("cpp_switch")
                .effect("invoke"),
        )
        .bind(
            "forward_goto",
            PointSelector::new("goto cpp_target;")
                .occurrence(0)
                .procedure("cpp_jump")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "backward_goto",
            PointSelector::new("goto cpp_target;")
                .occurrence(1)
                .procedure("cpp_jump")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "dead_jump_invoke",
            PointSelector::new("cpp_dead()")
                .procedure("cpp_jump")
                .effect("invoke"),
        )
        .bind(
            "live_invoke",
            PointSelector::new("cpp_live()")
                .procedure("cpp_jump")
                .effect("invoke"),
        )
        .bind(
            "jump_done_invoke",
            PointSelector::new("cpp_done()")
                .procedure("cpp_jump")
                .effect("invoke"),
        )
        .bind(
            "try_entry",
            PointSelector::new("void cpp_try(bool fail)")
                .procedure("cpp_try")
                .effect("entry"),
        )
        .bind(
            "throw",
            PointSelector::new("throw 7;")
                .procedure("cpp_try")
                .effect("throw"),
        )
        .bind(
            "catch_dispatch",
            PointSelector::new(try_source)
                .procedure("cpp_try")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "catch_entry",
            PointSelector::new(catch_source)
                .procedure("cpp_try")
                .effect("gap"),
        )
        .bind(
            "dead_throw_invoke",
            PointSelector::new("cpp_dead_throw()")
                .procedure("cpp_try")
                .effect("invoke"),
        )
        .bind(
            "normal_invoke",
            PointSelector::new("cpp_normal()")
                .procedure("cpp_try")
                .effect("invoke"),
        )
        .bind(
            "normal_exceptional",
            PointSelector::new("cpp_normal()")
                .procedure("cpp_try")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "handled_invoke",
            PointSelector::new("cpp_handled()")
                .procedure("cpp_try")
                .effect("invoke"),
        )
        .bind(
            "after_try_invoke",
            PointSelector::new("cpp_after_try()")
                .procedure("cpp_try")
                .effect("invoke"),
        )
        .bind(
            "try_exceptional_exit",
            PointSelector::new("void cpp_try(bool fail)")
                .procedure("cpp_try")
                .effect("exceptional_exit"),
        );

    graph.assert_reachable("switch_dispatch", "first_invoke");
    graph.assert_reachable("switch_dispatch", "second_invoke");
    graph.assert_reachable("switch_dispatch", "fallback_invoke");
    graph.assert_reachable("first_normal", "second_invoke");
    graph.assert_successors(
        "second_normal",
        &[cfg_edge("switch_break", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "switch_break",
        &[cfg_edge("second_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("switch_break", "after_switch_invoke");
    graph.assert_reachable("fallback_normal", "after_switch_invoke");

    graph.assert_reachable("forward_goto", "live_invoke");
    graph.assert_unreachable("forward_goto", "dead_jump_invoke");
    graph.assert_reachable("live_invoke", "backward_goto");
    graph.assert_reachable("backward_goto", "live_invoke");
    graph.assert_reachable("backward_goto", "jump_done_invoke");
    for transfer in ["forward_goto", "backward_goto"] {
        graph.assert_point_gap(
            transfer,
            SemanticCapability::NonLocalControl,
            SemanticGapKind::Unknown,
        );
        for capability in [
            SemanticCapability::CleanupControlFlow,
            SemanticCapability::ResourceManagement,
            SemanticCapability::Calls,
            SemanticCapability::ExceptionalControlFlow,
        ] {
            graph.assert_point_gap(transfer, capability, SemanticGapKind::Unknown);
        }
    }

    graph.assert_successors(
        "throw",
        &[cfg_edge("catch_dispatch", ControlEdgeKind::Exceptional)],
    );
    graph.assert_predecessors(
        "catch_dispatch",
        &[
            cfg_edge("throw", ControlEdgeKind::Exceptional),
            cfg_edge("normal_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_reachable("catch_dispatch", "handled_invoke");
    graph.assert_reachable("catch_dispatch", "try_exceptional_exit");
    graph.assert_reachable("try_entry", "normal_invoke");
    graph.assert_unreachable("try_entry", "dead_throw_invoke");
    graph.assert_reachable("handled_invoke", "after_try_invoke");
    graph.assert_point_gap(
        "catch_dispatch",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    for capability in [
        SemanticCapability::Calls,
        SemanticCapability::ExceptionalControlFlow,
        SemanticCapability::ResourceManagement,
    ] {
        graph.assert_point_gap("catch_entry", capability, SemanticGapKind::Unknown);
    }
    graph.assert_point_gap(
        "catch_entry",
        SemanticCapability::Values,
        SemanticGapKind::Unknown,
    );
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn cpp_callables_lifetimes_dispatch_and_unevaluated_operands_have_exact_gaps() {
    let source = r#"void cpp_cleanup(int value);
int cpp_hidden();
int cpp_combine(int left, int right);

struct Box {
    Box(int seed) : value(seed) {}
    ~Box() { cpp_cleanup(value); }
    int operator+(int rhs) const { return value + rhs; }
    virtual int run(int input) { return input; }
    int value;
};

int cpp_use(Box* pointer, int (*callback)(int), int left, int right) {
    Box local(left);
    int virtual_value = pointer->run(left);
    int indirect_value = (*callback)(right);
    std::thread worker{cpp_cleanup, left};
    int ordered_value = cpp_combine(left, right);
    int unevaluated_value = noexcept(cpp_hidden());
    Box* heap = new Box(right);
    int overloaded_value = local + left;
    return virtual_value + indirect_value + ordered_value + unevaluated_value
        + overloaded_value + heap->value;
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("cpp/callable_gaps.cpp", source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "cpp/callable_gaps.cpp");
    graph
        .bind(
            "constructor_entry",
            PointSelector::new("Box(int seed)")
                .procedure("Box")
                .effect("entry"),
        )
        .bind(
            "destructor_entry",
            PointSelector::new("~Box()")
                .procedure("~Box")
                .effect("entry"),
        )
        .bind(
            "local_initialization",
            PointSelector::new("Box local(left);")
                .procedure("cpp_use")
                .effect("gap"),
        )
        .bind(
            "thread_spawn",
            PointSelector::new("std::thread worker{cpp_cleanup, left};")
                .procedure("cpp_use")
                .effect("gap"),
        )
        .bind(
            "virtual_invoke",
            PointSelector::new("pointer->run(left)")
                .procedure("cpp_use")
                .effect("invoke"),
        )
        .bind(
            "new_invoke",
            PointSelector::new("new Box(right)")
                .procedure("cpp_use")
                .effect("invoke"),
        )
        .bind(
            "unevaluated",
            PointSelector::new("noexcept(cpp_hidden())")
                .procedure("cpp_use")
                .effect("gap"),
        )
        .bind(
            "overloaded_operator",
            PointSelector::new("local + left")
                .procedure("cpp_use")
                .effect("gap"),
        )
        .bind(
            "use_normal_exit",
            PointSelector::new(
                "int cpp_use(Box* pointer, int (*callback)(int), int left, int right)",
            )
            .procedure("cpp_use")
            .effect("normal_exit"),
        )
        .bind(
            "use_exceptional_exit",
            PointSelector::new(
                "int cpp_use(Box* pointer, int (*callback)(int), int left, int right)",
            )
            .procedure("cpp_use")
            .effect("exceptional_exit"),
        );

    let constructor = procedure_named(&graph, "Box", ProcedureKind::Constructor);
    let destructor = procedure_named(&graph, "~Box", ProcedureKind::Method);
    let operator = procedure_named(&graph, "operator+", ProcedureKind::Operator);
    let method = procedure_named(&graph, "run", ProcedureKind::Method);
    let use_procedure = procedure_named(&graph, "cpp_use", ProcedureKind::Function);
    for procedure in [constructor, destructor, operator, method, use_procedure] {
        assert_eq!(
            procedure.properties().invocation,
            ProcedureInvocationKind::Immediate
        );
    }

    for boundary in ["constructor_entry", "destructor_entry"] {
        for capability in [
            SemanticCapability::Calls,
            SemanticCapability::ExceptionalControlFlow,
            SemanticCapability::ResourceManagement,
        ] {
            graph.assert_point_gap(boundary, capability, SemanticGapKind::Unknown);
        }
    }
    for capability in [
        SemanticCapability::Calls,
        SemanticCapability::ExceptionalControlFlow,
        SemanticCapability::ResourceManagement,
    ] {
        graph.assert_point_gap("local_initialization", capability, SemanticGapKind::Unknown);
        graph.assert_point_gap("new_invoke", capability, SemanticGapKind::Unknown);
    }
    for boundary in ["use_normal_exit", "use_exceptional_exit"] {
        for capability in [
            SemanticCapability::CleanupControlFlow,
            SemanticCapability::ResourceManagement,
            SemanticCapability::Calls,
            SemanticCapability::ExceptionalControlFlow,
        ] {
            graph.assert_point_gap(boundary, capability, SemanticGapKind::Unknown);
        }
    }

    graph.assert_point_gap(
        "virtual_invoke",
        SemanticCapability::DynamicDispatch,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "thread_spawn",
        SemanticCapability::ConcurrentSpawn,
        SemanticGapKind::Unknown,
    );
    assert_call_site_gap(
        use_procedure,
        source,
        "(*callback)(right)",
        SemanticCapability::CallableReferences,
        SemanticGapKind::Unsupported,
    );
    assert_call_site_gap(
        use_procedure,
        source,
        "(*callback)(right)",
        SemanticCapability::Calls,
        SemanticGapKind::Unsupported,
    );
    assert_call_site_gap(
        use_procedure,
        source,
        "cpp_combine(left, right)",
        SemanticCapability::NormalControlFlow,
        SemanticGapKind::Unknown,
    );
    assert_call_site_gap(
        use_procedure,
        source,
        "new Box(right)",
        SemanticCapability::Allocations,
        SemanticGapKind::Unknown,
    );
    assert_no_exact_call_site(use_procedure, source, "cpp_hidden()");
    graph.assert_point_gap(
        "unevaluated",
        SemanticCapability::Values,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "unevaluated",
        SemanticCapability::Calls,
        SemanticGapKind::Unsupported,
    );
    for capability in [
        SemanticCapability::Calls,
        SemanticCapability::ExceptionalControlFlow,
    ] {
        graph.assert_point_gap("overloaded_operator", capability, SemanticGapKind::Unknown);
    }
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn cpp_preprocessing_publishes_exact_configuration_gaps() {
    let preprocessor_source = r#"#if CPP_FEATURE
    return cpp_feature(value);
#else
    return value;
#endif"#;
    let configured_source = format!(
        r#"int cpp_feature(int value);

int cpp_configured(int value) {{
{preprocessor_source}
}}
"#
    );
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("cpp/configured.cpp", &configured_source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut configured_graph =
        SemanticGraph::materialize(&project, &analyzer, "cpp/configured.cpp");
    configured_graph.bind(
        "configuration_dispatch",
        PointSelector::new(preprocessor_source)
            .procedure("cpp_configured")
            .outgoing_kind(ControlEdgeKind::SwitchCase),
    );
    let configured = procedure_named(&configured_graph, "cpp_configured", ProcedureKind::Function);
    for capability in [
        SemanticCapability::NormalControlFlow,
        SemanticCapability::Calls,
        SemanticCapability::CallableReferences,
    ] {
        assert_procedure_gap(configured, capability, SemanticGapKind::Unsupported);
    }
    for capability in [
        SemanticCapability::NormalControlFlow,
        SemanticCapability::Calls,
        SemanticCapability::NonLocalControl,
    ] {
        configured_graph.assert_point_gap(
            "configuration_dispatch",
            capability,
            SemanticGapKind::Unsupported,
        );
    }
    configured_graph.assert_adjacency_symmetric();
    let configured_render = configured_graph.render_topology();
    assert_eq!(configured_render, configured_graph.render_topology());
    assert!(!configured_render.contains("ProgramPointId"));
    assert!(!configured_render.contains("ControlEdgeId"));
}

#[test]
fn cpp_coroutines_publish_exact_suspension_gaps() {
    let coroutine_source = r#"int cpp_awaitable();

void cpp_coroutine() {
    co_await cpp_awaitable();
    co_yield 1;
    co_return;
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("cpp/coroutine.cpp", coroutine_source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut coroutine_graph = SemanticGraph::materialize(&project, &analyzer, "cpp/coroutine.cpp");
    coroutine_graph
        .bind(
            "await_invoke",
            PointSelector::new("cpp_awaitable()")
                .procedure("cpp_coroutine")
                .effect("invoke"),
        )
        .bind(
            "await_normal",
            PointSelector::new("cpp_awaitable()")
                .procedure("cpp_coroutine")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "await_exceptional",
            PointSelector::new("cpp_awaitable()")
                .procedure("cpp_coroutine")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        );
    let coroutine = procedure_named(&coroutine_graph, "cpp_coroutine", ProcedureKind::Function);
    assert!(coroutine.properties().is_async);
    assert!(coroutine.properties().is_generator);
    assert_eq!(
        coroutine.properties().invocation,
        ProcedureInvocationKind::Deferred
    );
    for capability in [
        SemanticCapability::DeferredExecution,
        SemanticCapability::AsyncSuspendResume,
        SemanticCapability::GeneratorSuspension,
    ] {
        assert_procedure_gap(coroutine, capability, SemanticGapKind::Unsupported);
    }
    for point_source in ["co_await cpp_awaitable()", "co_yield 1;", "co_return;"] {
        for capability in [
            SemanticCapability::AsyncSuspendResume,
            SemanticCapability::DeferredExecution,
        ] {
            assert_source_point_gap(
                coroutine,
                coroutine_source,
                point_source,
                capability,
                SemanticGapKind::Unsupported,
            );
        }
    }
    coroutine_graph.assert_successors(
        "await_invoke",
        &[
            cfg_edge("await_normal", ControlEdgeKind::Normal),
            cfg_edge("await_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    coroutine_graph.assert_predecessors(
        "await_normal",
        &[cfg_edge("await_invoke", ControlEdgeKind::Normal)],
    );
    coroutine_graph.assert_adjacency_symmetric();
    let coroutine_render = coroutine_graph.render_topology();
    assert_eq!(coroutine_render, coroutine_graph.render_topology());
    assert!(!coroutine_render.contains("ProgramPointId"));
    assert!(!coroutine_render.contains("ControlEdgeId"));
}

#[test]
fn cpp_order_scope_cleanup_and_local_static_uncertainty_are_point_scoped() {
    let inner_block = r#"{
        Guard local(sum);
        cpp_left();
    }"#;
    let source = format!(
        r#"int cpp_left();
int cpp_right();

struct Guard {{
    Guard(int value);
    ~Guard();
}};

struct Pair {{
    int first;
    int second;
    Pair() : second(cpp_right()), first(cpp_left()) {{}}
}};

int cpp_boundaries() {{
    int sum = cpp_left() + cpp_right();
    {inner_block}
    static Guard shared(cpp_right());
    return sum;
}}
"#
    );
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("cpp/order_and_lifetime.cpp", &source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "cpp/order_and_lifetime.cpp");
    graph
        .bind(
            "binary_order",
            PointSelector::new("cpp_left() + cpp_right()")
                .procedure("cpp_boundaries")
                .effect("gap"),
        )
        .bind(
            "constructor_order",
            PointSelector::new(": second(cpp_right()), first(cpp_left())")
                .procedure("Pair")
                .effect("gap"),
        )
        .bind(
            "inner_scope_exit",
            PointSelector::new(inner_block)
                .procedure("cpp_boundaries")
                .effect("gap"),
        )
        .bind(
            "static_guard",
            PointSelector::new("static Guard shared(cpp_right());")
                .procedure("cpp_boundaries")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        );

    for boundary in ["binary_order", "constructor_order", "static_guard"] {
        graph.assert_point_gap(
            boundary,
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unknown,
        );
    }
    for capability in [
        SemanticCapability::CleanupControlFlow,
        SemanticCapability::ResourceManagement,
    ] {
        graph.assert_point_gap("inner_scope_exit", capability, SemanticGapKind::Unknown);
    }
    graph.assert_point_gap(
        "static_guard",
        SemanticCapability::DeferredExecution,
        SemanticGapKind::Unknown,
    );
    let procedure = procedure_named(&graph, "cpp_boundaries", ProcedureKind::Function);
    let static_gap = procedure
        .gaps()
        .iter()
        .find(|gap| {
            gap.capability == SemanticCapability::DeferredExecution
                && gap.detail.contains("function-local static initialization")
        })
        .expect("missing guarded C++ local-static deferred-execution gap");
    assert_deferred_effect_impacts(static_gap, false, "guarded C++ local-static initializer");
    graph.assert_adjacency_symmetric();
}

#[test]
fn c_vla_bound_calls_are_retained_in_declaration_flow() {
    let source = r#"int c_next_size(void) { return 4; }

void c_vla(void) {
    int values[c_next_size()];
    values[0] = 1;
    {
        int nested[c_next_size()];
        if (values[0]) return;
        nested[0] = values[0];
    }
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("c/vla.c", source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "c/vla.c");
    graph
        .bind(
            "vla_invoke",
            PointSelector::new("c_next_size()")
                .occurrence(1)
                .procedure("c_vla")
                .effect("invoke"),
        )
        .bind(
            "vla_normal",
            PointSelector::new("c_next_size()")
                .occurrence(1)
                .procedure("c_vla")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "vla_exceptional",
            PointSelector::new("c_next_size()")
                .occurrence(1)
                .procedure("c_vla")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "vla_normal_exit",
            PointSelector::new("void c_vla(void)")
                .procedure("c_vla")
                .effect("normal_exit"),
        )
        .bind(
            "vla_exceptional_exit",
            PointSelector::new("void c_vla(void)")
                .procedure("c_vla")
                .effect("exceptional_exit"),
        );
    let procedure = procedure_named(&graph, "c_vla", ProcedureKind::Function);
    assert_eq!(
        call_site_source(
            procedure,
            source,
            exact_call_site(procedure, source, "c_next_size()")
        ),
        "c_next_size()"
    );
    graph.assert_successors(
        "vla_invoke",
        &[
            cfg_edge("vla_normal", ControlEdgeKind::Normal),
            cfg_edge("vla_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    for capability in [
        SemanticCapability::CleanupControlFlow,
        SemanticCapability::ResourceManagement,
        SemanticCapability::Allocations,
    ] {
        assert_procedure_gap(procedure, capability, SemanticGapKind::Unknown);
        graph.assert_point_gap("vla_normal_exit", capability, SemanticGapKind::Unknown);
        graph.assert_point_gap("vla_exceptional_exit", capability, SemanticGapKind::Unknown);
        assert_source_point_gap(
            procedure,
            source,
            "return;",
            capability,
            SemanticGapKind::Unknown,
        );
    }
    graph.assert_adjacency_symmetric();
}

#[test]
fn cpp_nested_cases_and_seh_bodies_are_retained_without_false_fallthrough() {
    let outer_switch = r#"switch (value) {
        if (flag) {
            case 1:
                cpp_nested();
                break;
        }
        case 2:
            switch (value) {
                case 3:
                    cpp_inner();
                    break;
            }
            break;
        default:
            cpp_fallback();
    }"#;
    let seh_except = r#"__try {
        cpp_try_body();
    } __except(cpp_filter()) {
        cpp_handler();
    }"#;
    let source = format!(
        r#"int cpp_filter();
void cpp_nested();
void cpp_inner();
void cpp_fallback();
void cpp_try_body();
void cpp_handler();
void cpp_finally_body();
void cpp_cleanup();
void cpp_after_leave();

void cpp_control(int value, bool flag) {{
    {outer_switch}
    {seh_except}
    __try {{
        cpp_finally_body();
    }} __finally {{
        cpp_cleanup();
    }}
    __try {{
        __leave;
        cpp_after_leave();
    }} __finally {{
        cpp_cleanup();
    }}
}}
"#
    );
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("cpp/switch_seh.cpp", &source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "cpp/switch_seh.cpp");
    graph
        .bind(
            "outer_dispatch",
            PointSelector::new(outer_switch)
                .procedure("cpp_control")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "outer_case_one",
            PointSelector::new("case 1:\n                cpp_nested();\n                break;")
                .procedure("cpp_control")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "outer_case_two",
            PointSelector::new(
                r#"case 2:
            switch (value) {
                case 3:
                    cpp_inner();
                    break;
            }
            break;"#,
            )
            .procedure("cpp_control")
            .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "outer_default",
            PointSelector::new("default:\n            cpp_fallback();")
                .procedure("cpp_control")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "inner_dispatch",
            PointSelector::new(
                r#"switch (value) {
                case 3:
                    cpp_inner();
                    break;
            }"#,
            )
            .procedure("cpp_control")
            .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "inner_case",
            PointSelector::new(
                "case 3:\n                    cpp_inner();\n                    break;",
            )
            .procedure("cpp_control")
            .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "seh_boundary",
            PointSelector::new(seh_except)
                .procedure("cpp_control")
                .effect("gap"),
        )
        .bind(
            "seh_leave",
            PointSelector::new("__leave;")
                .procedure("cpp_control")
                .effect("gap"),
        )
        .bind(
            "after_leave",
            PointSelector::new("cpp_after_leave()")
                .procedure("cpp_control")
                .effect("invoke"),
        );

    graph.assert_successors(
        "outer_dispatch",
        &[
            cfg_edge("outer_case_one", ControlEdgeKind::SwitchCase),
            cfg_edge("outer_case_two", ControlEdgeKind::SwitchCase),
            cfg_edge("outer_default", ControlEdgeKind::SwitchCase),
        ],
    );
    graph.assert_predecessors(
        "outer_case_one",
        &[cfg_edge("outer_dispatch", ControlEdgeKind::SwitchCase)],
    );
    graph.assert_predecessors(
        "inner_case",
        &[cfg_edge("inner_dispatch", ControlEdgeKind::SwitchCase)],
    );
    for capability in [
        SemanticCapability::NormalControlFlow,
        SemanticCapability::ExceptionalControlFlow,
        SemanticCapability::CleanupControlFlow,
        SemanticCapability::Calls,
        SemanticCapability::NonLocalControl,
        SemanticCapability::ResourceManagement,
    ] {
        graph.assert_point_gap("seh_boundary", capability, SemanticGapKind::Unsupported);
    }
    for capability in [
        SemanticCapability::NormalControlFlow,
        SemanticCapability::CleanupControlFlow,
        SemanticCapability::NonLocalControl,
    ] {
        graph.assert_point_gap("seh_leave", capability, SemanticGapKind::Unsupported);
    }
    let procedure = procedure_named(&graph, "cpp_control", ProcedureKind::Function);
    assert_eq!(
        procedure
            .call_sites()
            .iter()
            .filter(|call| call_site_source(procedure, &source, call) == "cpp_nested()")
            .count(),
        1,
        "nested case body must be lowered exactly once"
    );
    for call in [
        "cpp_try_body()",
        "cpp_filter()",
        "cpp_handler()",
        "cpp_finally_body()",
        "cpp_cleanup()",
        "cpp_after_leave()",
    ] {
        let _ = exact_call_site(procedure, &source, call);
    }
    graph.assert_unreachable("seh_leave", "after_leave");
    graph.assert_adjacency_symmetric();
}

#[test]
fn cpp_enumeration_budget_counts_non_callable_syntax() {
    let source = (0..64)
        .map(|index| format!("struct Budget{index} {{ int value; }};\n"))
        .collect::<String>();
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("cpp/enumeration_budget.cpp", &source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("cpp/enumeration_budget.cpp");
    let cancellation = CancellationToken::default();

    let mut limits = SemanticBudget::default().limits();
    limits.nested_entries = 12;
    let mut budget = SemanticBudget::new(limits).expect("positive semantic budget");
    let outcome = analyzer
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .expect("enumeration exhaustion is a semantic outcome");
    assert!(matches!(
        outcome,
        SemanticOutcome::ExceededBudget { exceeded, work, .. }
            if exceeded.dimension() == SemanticBudgetDimension::NestedEntries
                && work.nested_entries > 12
    ));

    let mut budget = SemanticBudget::default();
    let outcome = analyzer
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .expect("sufficient enumeration budget");
    assert!(matches!(
        outcome,
        SemanticOutcome::Complete { work, .. } if work.nested_entries > 64
    ));
}

#[test]
fn cpp_deep_parenthesized_member_receiver_is_stack_safe() {
    const DEPTH: usize = 2_048;
    let mut callee = "receiver->direct".to_string();
    for _ in 0..DEPTH {
        callee = format!("({callee})");
    }
    let source = format!(
        r#"struct Receiver {{
    int direct() {{ return 1; }}
}};

int cpp_deep_receiver(Receiver* receiver) {{
    return {callee}();
}}
"#
    );
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("cpp/deep_receiver.cpp", &source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "cpp/deep_receiver.cpp");
    let procedure = procedure_named(&graph, "cpp_deep_receiver", ProcedureKind::Function);
    let call = procedure
        .call_sites()
        .first()
        .expect("deep parenthesized member call");
    assert!(call.receiver.is_some());
    assert!(procedure.gaps().iter().any(|gap| {
        gap.point == call.point && gap.capability == SemanticCapability::DynamicDispatch
    }));
    graph.assert_adjacency_symmetric();
}

#[test]
fn c_assignment_call_operand_order_and_gnu_asm_publish_exact_gaps() {
    let asm = r#"asm goto("test %0; jnz %l1" : : "r"(value) : "cc" : target);"#;
    let source = format!(
        r#"int c_bump(int *value);
int c_argument(void);
int (*c_next_callback(void))(int);
void c_after(void);
void c_done(void);

int c_order(int *pointer, int value) {{
    *pointer = c_bump(pointer);
    int result = c_next_callback()(c_argument());
    {asm}
    c_after();
target:
    c_done();
    return result;
}}
"#
    );
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("c/order_and_asm.c", &source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "c/order_and_asm.c");
    let procedure = procedure_named(&graph, "c_order", ProcedureKind::Function);
    assert_source_point_gap(
        procedure,
        &source,
        "*pointer = c_bump(pointer)",
        SemanticCapability::NormalControlFlow,
        SemanticGapKind::Unknown,
    );
    assert_call_site_gap(
        procedure,
        &source,
        "c_next_callback()(c_argument())",
        SemanticCapability::NormalControlFlow,
        SemanticGapKind::Unknown,
    );
    for capability in [
        SemanticCapability::NormalControlFlow,
        SemanticCapability::NonLocalControl,
        SemanticCapability::Calls,
        SemanticCapability::Values,
        SemanticCapability::Assignments,
    ] {
        assert_source_point_gap(
            procedure,
            &source,
            asm,
            capability,
            SemanticGapKind::Unsupported,
        );
    }
    graph.assert_adjacency_symmetric();
}

#[test]
fn cpp_cross_file_member_call_requires_dynamic_dispatch_refinement() {
    let header = r#"struct Base {
    virtual int run();
};
"#;
    let caller_source = r#"#include "base.h"
int cpp_cross_file_dispatch(Base* receiver) {
    return receiver->run();
}
"#;
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("cpp/base.h", header)
        .file("cpp/caller.cpp", caller_source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "cpp/caller.cpp");
    let procedure = procedure_named(&graph, "cpp_cross_file_dispatch", ProcedureKind::Function);
    let call = exact_call_site(procedure, caller_source, "receiver->run()");
    assert!(procedure.gaps().iter().any(|gap| {
        gap.point == call.point
            && gap.subject == SemanticGapSubject::Point
            && gap.capability == SemanticCapability::DynamicDispatch
            && gap.kind == SemanticGapKind::Unknown
    }));
    graph.assert_adjacency_symmetric();
}

#[test]
fn cpp_statement_condition_and_range_cleanup_boundaries_are_exact() {
    let if_condition = "(Guard if_guard{make_if_guard()}; flag)";
    let for_initializer = "Guard for_guard{make_for_guard()};";
    let switch_condition = "(Guard switch_guard{make_switch_guard()}; tag)";
    let range_loop = r#"for (Guard item : make_range()) {
        if (flag) continue;
        break;
    }"#;
    let source = format!(
        r#"struct Guard {{
    Guard();
    ~Guard();
}};
struct Range {{}};

Guard make_if_guard();
Guard make_for_guard();
Guard make_switch_guard();
Range make_range();
void touch();
void step();
void after();

void cpp_cleanup_boundaries(bool flag, int tag) {{
    if {if_condition} touch();
    for ({for_initializer} flag; step()) {{
        if (flag) continue;
        break;
    }}
    switch {switch_condition} {{
        default: break;
    }}
    {range_loop}
    after();
}}
"#
    );
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("cpp/statement_cleanup.cpp", &source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "cpp/statement_cleanup.cpp");
    let procedure = procedure_named(&graph, "cpp_cleanup_boundaries", ProcedureKind::Function);
    for call in [
        "make_if_guard()",
        "make_for_guard()",
        "make_switch_guard()",
        "make_range()",
    ] {
        let _ = exact_call_site(procedure, &source, call);
    }
    for boundary in [if_condition, for_initializer, switch_condition, range_loop] {
        for capability in [
            SemanticCapability::CleanupControlFlow,
            SemanticCapability::ResourceManagement,
        ] {
            assert_source_point_gap(
                procedure,
                &source,
                boundary,
                capability,
                SemanticGapKind::Unknown,
            );
        }
    }
    let range_cleanup_points = procedure
        .points()
        .iter()
        .filter(|point| {
            let Some(mapping) = procedure.source_mapping(point.source) else {
                return false;
            };
            let span = mapping.locator.anchor().span();
            source.get(span.start_byte() as usize..span.end_byte() as usize) == Some(range_loop)
                && point.events.iter().any(|event| {
                    let SemanticEffect::Gap { gap } = &event.effect else {
                        return false;
                    };
                    procedure.gap(*gap).is_some_and(|gap| {
                        gap.subject == SemanticGapSubject::Point
                            && gap.capability == SemanticCapability::CleanupControlFlow
                    })
                })
        })
        .count();
    assert_eq!(
        range_cleanup_points, 3,
        "range lifetime, normal/continue binding cleanup, and break binding cleanup must remain distinct"
    );
    graph.assert_adjacency_symmetric();
}

#[test]
fn cpp_noexcept_specs_route_or_downgrade_exceptional_completion() {
    let unconditional = r#"void cpp_noexcept() noexcept {
    cpp_risky();
    throw 1;
}"#;
    let conditional = r#"void cpp_conditional_noexcept() noexcept(sizeof(int) == 4) {
    throw 2;
}"#;
    let source = format!(
        r#"void cpp_risky();

{unconditional}

{conditional}

void cpp_may_throw() noexcept(false) {{
    throw 3;
}}
"#
    );
    let project = InlineTestProject::with_language(Language::Cpp)
        .file("cpp/noexcept.cpp", &source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "cpp/noexcept.cpp");
    graph
        .bind(
            "noexcept_throw",
            PointSelector::new("throw 1;")
                .procedure("cpp_noexcept")
                .effect("throw"),
        )
        .bind(
            "noexcept_call_exceptional",
            PointSelector::new("cpp_risky()")
                .procedure("cpp_noexcept")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "noexcept_exceptional_exit",
            PointSelector::new("void cpp_noexcept()")
                .procedure("cpp_noexcept")
                .effect("exceptional_exit"),
        )
        .bind(
            "conditional_exceptional_exit",
            PointSelector::new("void cpp_conditional_noexcept()")
                .procedure("cpp_conditional_noexcept")
                .effect("exceptional_exit"),
        );

    let noexcept = procedure_named(&graph, "cpp_noexcept", ProcedureKind::Function);
    let conditional_noexcept =
        procedure_named(&graph, "cpp_conditional_noexcept", ProcedureKind::Function);
    for capability in [
        SemanticCapability::ExceptionalControlFlow,
        SemanticCapability::NonLocalControl,
        SemanticCapability::Calls,
    ] {
        assert_procedure_gap(noexcept, capability, SemanticGapKind::Unknown);
        assert_source_point_gap(
            noexcept,
            &source,
            unconditional,
            capability,
            SemanticGapKind::Unknown,
        );
        assert_procedure_gap(conditional_noexcept, capability, SemanticGapKind::Unknown);
        graph.assert_point_gap(
            "conditional_exceptional_exit",
            capability,
            SemanticGapKind::Unknown,
        );
    }
    graph.assert_unreachable("noexcept_throw", "noexcept_exceptional_exit");
    graph.assert_unreachable("noexcept_call_exceptional", "noexcept_exceptional_exit");
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
    let deferred_gap = schedule
        .gaps()
        .iter()
        .find(|gap| {
            gap.capability == SemanticCapability::DeferredExecution
                && gap.detail.contains("deferred invocation timing")
        })
        .expect("missing omitted Go defer invocation gap");
    assert_deferred_effect_impacts(deferred_gap, false, "omitted Go defer invocation");
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
            "target_operation_boundary",
            PointSelector::new("sink[index()]")
                .procedure("rangeFlow")
                .effect("gap")
                .anchor_occurrence(3)
                .outgoing_kind(ControlEdgeKind::Normal),
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
        &[cfg_edge(
            "target_operation_boundary",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_point_gap(
        "target_operation_boundary",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_successors(
        "target_operation_boundary",
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
fn go_builtin_new_shadowing_remains_lexically_structured_after_file_precomputation() {
    const LEXICAL_SOURCE: &str = r#"package conformance

type Service struct{}
func (*Service) Run() {}
func makeNew(value any) *Service { return nil }

func builtin() {
    new(Service).Run()
}

func localShadow() {
    new := makeNew
    new(Service).Run()
}

func namedResultShadow() (new func(any) *Service) {
    new(Service).Run()
    return
}
"#;
    let project = InlineTestProject::with_language(Language::Go)
        .file("go/new_lexical_shadow.go", LEXICAL_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "go/new_lexical_shadow.go");

    let has_new_allocation = |procedure_name: &str| {
        let procedure = procedure_named(&graph, procedure_name, ProcedureKind::Function);
        procedure.allocations().iter().any(|allocation| {
            let mapping = procedure
                .source_mapping(allocation.source)
                .expect("Go allocation must retain a source mapping");
            let span = mapping.locator.anchor().span();
            LEXICAL_SOURCE.get(span.start_byte() as usize..span.end_byte() as usize)
                == Some("new(Service)")
        })
    };

    assert!(
        has_new_allocation("builtin"),
        "the unshadowed predeclared new must remain an allocation"
    );
    for procedure_name in ["localShadow", "namedResultShadow"] {
        assert!(
            !has_new_allocation(procedure_name),
            "{procedure_name} must treat its lexical new binding as an ordinary call"
        );
        let procedure = procedure_named(&graph, procedure_name, ProcedureKind::Function);
        let _ = exact_call_site(procedure, LEXICAL_SOURCE, "new(Service)");
    }

    const PACKAGE_SOURCE: &str = r#"package conformance

type Service struct{}
func (*Service) Run() {}
func new(value any) *Service { return nil }

func first() {
    new(Service).Run()
}

func second() {
    new(Service).Run()
}
"#;
    let project = InlineTestProject::with_language(Language::Go)
        .file("go/new_package_shadow.go", PACKAGE_SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "go/new_package_shadow.go");

    for procedure_name in ["first", "second"] {
        let procedure = procedure_named(&graph, procedure_name, ProcedureKind::Function);
        assert!(
            procedure.allocations().iter().all(|allocation| {
                let mapping = procedure
                    .source_mapping(allocation.source)
                    .expect("Go allocation must retain a source mapping");
                let span = mapping.locator.anchor().span();
                PACKAGE_SOURCE.get(span.start_byte() as usize..span.end_byte() as usize)
                    != Some("new(Service)")
            }),
            "one package-level new declaration must shadow the builtin in every procedure"
        );
        let _ = exact_call_site(procedure, PACKAGE_SOURCE, "new(Service)");
    }
}

#[test]
fn go_many_procedure_enumeration_is_budgeted_without_double_counting_identity_work() {
    let mut source = String::from("package conformance\n\ntype Service struct{}\n");
    for index in 0..64 {
        source.push_str(&format!("func procedure{index}() {{ _ = new(Service) }}\n"));
    }
    let project = InlineTestProject::with_language(Language::Go)
        .file("go/many_procedures.go", &source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("go/many_procedures.go");
    let cancellation = CancellationToken::default();

    let mut limits = SemanticBudget::default().limits();
    limits.nested_entries = 12;
    let mut budget = SemanticBudget::new(limits).expect("positive semantic budget");
    let outcome = analyzer
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .expect("enumeration exhaustion is a semantic outcome");
    assert!(matches!(
        outcome,
        SemanticOutcome::ExceededBudget { exceeded, work, .. }
            if exceeded.dimension() == SemanticBudgetDimension::NestedEntries
                && work.nested_entries > 12
    ));

    let mut budget = SemanticBudget::default();
    let outcome = analyzer
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .expect("sufficient enumeration budget");
    let SemanticOutcome::Complete { value, work } = outcome else {
        panic!("sufficient enumeration budget must complete");
    };
    assert_eq!(value.procedures().len(), 64);
    assert_eq!(
        work.procedures,
        value.procedures().len(),
        "enumeration identity preflight must not be charged again when lowering starts"
    );
    assert!(
        work.nested_entries > value.procedures().len(),
        "the one-pass file traversal must be represented in semantic work"
    );
}

#[test]
fn go_wide_package_binding_inventory_stops_at_the_nested_entry_budget() {
    let names = (0..4_096)
        .map(|index| format!("binding{index} /* package binding {index} */"))
        .chain(std::iter::once("new".to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    let source = format!(
        "package conformance\n\nvar {names} int\n\nfunc use() {{ _ = new(Service{{}}) }}\n"
    );
    let project = InlineTestProject::with_language(Language::Go)
        .file("go/wide_package_binding.go", &source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("go/wide_package_binding.go");
    let cancellation = CancellationToken::default();
    let mut limits = SemanticBudget::default().limits();
    limits.nested_entries = 8;
    let mut budget = SemanticBudget::new(limits).expect("positive semantic budget");

    let outcome = analyzer
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .expect("wide package inventory exhaustion is a semantic outcome");
    let SemanticOutcome::ExceededBudget { exceeded, work, .. } = outcome else {
        panic!("wide Go package inventory must exhaust its nested-entry budget");
    };
    assert_eq!(exceeded.dimension(), SemanticBudgetDimension::NestedEntries);
    assert_eq!(work.nested_entries, limits.nested_entries + 1);
}

#[test]
fn python_wide_function_body_stops_at_the_nested_entry_budget() {
    let mut source = String::from("def wide():\n");
    for index in 0..4_096 {
        source.push_str(&format!("    value_{index} = {index}\n"));
    }
    let project = InlineTestProject::with_language(Language::Python)
        .file("python/wide_function.py", &source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let file = project.file("python/wide_function.py");
    let cancellation = CancellationToken::default();
    let mut limits = SemanticBudget::default().limits();
    limits.nested_entries = 8;
    let mut budget = SemanticBudget::new(limits).expect("positive semantic budget");

    let outcome = analyzer
        .materialize_program_semantics(&file, &mut SemanticRequest::new(&mut budget, &cancellation))
        .expect("wide Python enumeration exhaustion is a semantic outcome");
    let SemanticOutcome::ExceededBudget { exceeded, work, .. } = outcome else {
        panic!("wide Python enumeration must exhaust its nested-entry budget");
    };
    assert_eq!(exceeded.dimension(), SemanticBudgetDimension::NestedEntries);
    assert!(
        work.nested_entries > limits.nested_entries
            && work.nested_entries <= limits.nested_entries + 4,
        "enumeration must stop within one bounded identity-work increment, not after the 4,096-child body"
    );
}

#[test]
fn csharp_direct_call_conformance() {
    assert_closed_dispatch_direct_call_conformance(DirectCallFixture {
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

    graph.assert_outcome(IcfgOutcomeKind::Unproven);
    graph.assert_boundary(
        "async_invoke",
        ExpectedIcfgBoundary::new(ExpectedIcfgBoundaryKind::DispatchDeferred(
            DeferredInvocationKind::Async,
        ))
        .originating_call("async_call"),
    );
    graph.assert_boundary(
        "async_invoke",
        ExpectedIcfgBoundary::new(ExpectedIcfgBoundaryKind::DispatchUnresolved)
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
    graph.assert_boundary(
        "generator_invoke",
        ExpectedIcfgBoundary::new(ExpectedIcfgBoundaryKind::DispatchUnresolved)
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
            PointSelector::new("() =>")
                .procedure("src/features.js::type:Worker::initializer:run::lambda:run")
                .effect("entry"),
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
fn javascript_typescript_class_field_initializers_are_source_backed() {
    const SOURCE: &str = r#"
        function outer() {
            class Fields {
                named = () => this;
                static shared = () => this;
                [(() => "computed")()] = () => this;
                [(() => "direct")()] = this;
                declared;
            }
        }
    "#;

    let project = InlineTestProject::new()
        .file("javascript/fields.js", SOURCE)
        .file("javascript/fields.jsx", SOURCE)
        .file("typescript/fields.ts", SOURCE)
        .file("typescript/fields.tsx", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut baseline = None;

    for path in [
        "javascript/fields.js",
        "javascript/fields.jsx",
        "typescript/fields.ts",
        "typescript/fields.tsx",
    ] {
        let graph = SemanticGraph::materialize(&project, &analyzer, path);
        let procedures = graph.artifact().procedures();
        let outer = procedure_named(&graph, "outer", ProcedureKind::Function);
        let initializers = procedures
            .iter()
            .filter(|procedure| procedure.kind() == ProcedureKind::Initializer)
            .collect::<Vec<_>>();
        assert_eq!(
            initializers.len(),
            4,
            "{path} should publish one initializer for each field value and none for `declared`"
        );

        let named_initializer = initializers
            .iter()
            .copied()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("named")
            })
            .unwrap_or_else(|| panic!("{path} should retain the named field identity"));
        assert!(!named_initializer.properties().is_static);
        let static_initializer = initializers
            .iter()
            .copied()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("shared")
            })
            .unwrap_or_else(|| panic!("{path} should retain the static field identity"));
        assert!(static_initializer.properties().is_static);

        let mut anonymous_ordinals = initializers
            .iter()
            .filter_map(|procedure| {
                let segment = procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .expect("initializer declaration must have a final segment");
                segment
                    .name()
                    .is_none()
                    .then_some(segment.sibling_ordinal())
            })
            .collect::<Vec<_>>();
        anonymous_ordinals.sort_unstable();
        assert_eq!(anonymous_ordinals, [0, 1]);

        for initializer in &initializers {
            assert_eq!(initializer.lexical_parent(), Some(outer.id()));
            assert!(
                initializer
                    .locator()
                    .declaration()
                    .segments()
                    .iter()
                    .any(|segment| {
                        segment.kind() == DeclarationSegmentKind::Type
                            && segment.name() == Some("Fields")
                    }),
                "{path} initializer should remain nested under the class declaration"
            );
        }

        let lambdas = procedures
            .iter()
            .filter(|procedure| procedure.kind() == ProcedureKind::Lambda)
            .collect::<Vec<_>>();
        assert_eq!(lambdas.len(), 5);
        for lambda in &lambdas {
            let source = procedure_source(lambda, SOURCE);
            if source.contains("\"computed\"") || source.contains("\"direct\"") {
                assert_eq!(
                    lambda.lexical_parent(),
                    Some(outer.id()),
                    "{path} computed field names execute in the outer class-definition context"
                );
            } else {
                assert_eq!(source, "() => this");
                assert!(
                    initializers
                        .iter()
                        .any(|initializer| Some(initializer.id()) == lambda.lexical_parent()),
                    "{path} field-value arrows should be owned by their initializer procedure"
                );
            }
        }

        let projection = procedures
            .iter()
            .map(|procedure| {
                let final_segment = procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .expect("procedure declaration must have a final segment");
                (
                    procedure.kind(),
                    final_segment.name().map(str::to_owned),
                    final_segment.sibling_ordinal(),
                    procedure.properties().is_static,
                    procedure
                        .lexical_parent()
                        .and_then(|parent| procedures.get(parent.index()))
                        .map(ProcedureSemantics::kind),
                    procedure_source(procedure, SOURCE).to_owned(),
                )
            })
            .collect::<Vec<_>>();
        if let Some(baseline) = &baseline {
            assert_eq!(
                &projection, baseline,
                "{path} should preserve JS/JSX/TS/TSX procedure identity parity"
            );
        } else {
            baseline = Some(projection);
        }
    }
}

#[test]
fn typescript_unsupported_parameter_decorators_do_not_publish_nested_callables() {
    let project = InlineTestProject::with_language(Language::TypeScript)
        .file(
            "typescript/decorators.ts",
            r#"
                declare function decorate(value: unknown): ParameterDecorator;

                class Decorated {
                    method(@decorate(() => this) value: string): string {
                        return value;
                    }
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "typescript/decorators.ts");

    assert!(
        graph
            .artifact()
            .procedures()
            .iter()
            .all(|procedure| procedure.kind() != ProcedureKind::Lambda),
        "unsupported parameter decorators must not publish misleading nested callable semantics"
    );
    let method = procedure_named(&graph, "method", ProcedureKind::Method);
    assert!(
        method.captures().is_empty(),
        "the decorated method must not capture a decorator arrow through its own receiver"
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
            "using_assignment",
            PointSelector::new("resource = Acquire()")
                .procedure("Managed")
                .effect("assignment"),
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
            "declared_assignment",
            PointSelector::new("resource = AcquireDeclared()")
                .procedure("UsingDeclaration")
                .effect("assignment"),
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
        &[cfg_edge("using_assignment", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "using_assignment",
        &[cfg_edge("using_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "using_boundary",
        &[cfg_edge("using_assignment", ControlEdgeKind::Normal)],
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
        &[cfg_edge("declared_assignment", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "declared_assignment",
        &[cfg_edge(
            "after_using_declaration_statement",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_predecessors(
        "after_using_declaration_statement",
        &[cfg_edge("declared_assignment", ControlEdgeKind::Normal)],
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
                .anchor_occurrence(0),
        )
        .bind(
            "conditional_access_gap",
            PointSelector::new("[NextIndex()]")
                .procedure("ConditionalIndex")
                .effect("gap"),
        )
        .bind(
            "conditional_assignment",
            PointSelector::new("value = items?[NextIndex()]")
                .procedure("ConditionalIndex")
                .effect("assignment"),
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
        &[cfg_edge("indexed_access_gap", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "indexed_access_gap",
        &[cfg_edge("indexed_outer_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "indexed_outer_invoke",
        &[cfg_edge("indexed_access_gap", ControlEdgeKind::Normal)],
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
        "conditional_access_gap",
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
            cfg_edge("conditional_assignment", ControlEdgeKind::ConditionalFalse),
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
        &[cfg_edge("conditional_access_gap", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "conditional_access_gap",
        &[cfg_edge("conditional_assignment", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "conditional_assignment",
        &[
            cfg_edge("conditional_split", ControlEdgeKind::ConditionalFalse),
            cfg_edge("conditional_access_gap", ControlEdgeKind::Normal),
        ],
    );
    graph.assert_successors(
        "conditional_assignment",
        &[cfg_edge(
            "after_conditional_statement",
            ControlEdgeKind::Normal,
        )],
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
            PointSelector::new("P = G()")
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
            "variable_assignment",
            PointSelector::new("widget = new(F()) { P = G() }")
                .procedure("Build")
                .effect("assignment"),
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
        &[cfg_edge("initializer_property", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "initializer_property",
        &[cfg_edge("constructor_normal", ControlEdgeKind::Normal)],
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
        &[cfg_edge("initializer_assignment", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "initializer_assignment",
        &[cfg_edge("variable_assignment", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "variable_assignment",
        &[cfg_edge(
            "after_construction_statement",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_predecessors(
        "after_construction_statement",
        &[cfg_edge("variable_assignment", ControlEdgeKind::Normal)],
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
            "combine_assignment",
            PointSelector::new("result = combine(first(), second(inner()))")
                .procedure("evaluate")
                .effect("assignment"),
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
        &[cfg_edge("combine_assignment", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "combine_assignment",
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
            "value_assignment",
            PointSelector::new("outcome = first_value() < middle_value() < last_value()")
                .procedure("compare_value")
                .effect("assignment"),
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
        &[cfg_edge("value_assignment", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "value_assignment",
        &[cfg_edge("consume_value_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "consume_value_statement",
        &[cfg_edge("value_assignment", ControlEdgeKind::Normal)],
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
            "await_assignment",
            PointSelector::new("result = await fetch()")
                .procedure("await_one")
                .effect("assignment"),
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
        &[cfg_edge("await_assignment", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "await_assignment",
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
    assert_closed_dispatch_direct_call_conformance(DirectCallFixture {
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
    assert_closed_dispatch_direct_call_conformance(DirectCallFixture {
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

#[test]
fn scala_functions_methods_locals_and_lambdas_are_separate_immediate_procedures() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/Callables.scala",
            r#"
                package conformance

                def topLevel(): Int = {
                  topBody()
                  1
                }

                object Worker {
                  def method(): Int = {
                    methodBody()
                    2
                  }
                }

                def outer(): Int = {
                  def local(): Int = {
                    localBody()
                    3
                  }

                  val lambda = (value: Int) => { lambdaBody(value); value }
                  outerBody()
                  4
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "scala/Callables.scala");
    graph
        .bind(
            "top_entry",
            PointSelector::new("def topLevel(): Int")
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
            "method_entry",
            PointSelector::new("def method(): Int")
                .procedure("method")
                .effect("entry"),
        )
        .bind(
            "method_invoke",
            PointSelector::new("methodBody()")
                .procedure("method")
                .effect("invoke"),
        )
        .bind(
            "outer_entry",
            PointSelector::new("def outer(): Int")
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
            "local_entry",
            PointSelector::new("def local(): Int")
                .procedure("local")
                .effect("entry"),
        )
        .bind(
            "local_invoke",
            PointSelector::new("localBody()")
                .procedure("local")
                .effect("invoke"),
        )
        .bind(
            "lambda_entry",
            PointSelector::new("(value: Int) => { lambdaBody(value); value }").effect("entry"),
        )
        .bind(
            "lambda_invoke",
            PointSelector::new("lambdaBody(value)").effect("invoke"),
        );

    for (entry, invoke) in [
        ("top_entry", "top_invoke"),
        ("method_entry", "method_invoke"),
        ("outer_entry", "outer_invoke"),
        ("local_entry", "local_invoke"),
        ("lambda_entry", "lambda_invoke"),
    ] {
        graph.assert_reachable(entry, invoke);
    }
    for (body_call, procedure) in [("localBody()", "outer"), ("lambdaBody(value)", "outer")] {
        let error = graph
            .try_bind(
                format!("{procedure}_must_not_own_{body_call}"),
                PointSelector::new(body_call)
                    .procedure(procedure)
                    .effect("invoke"),
            )
            .expect_err("nested callable execution must stay outside the enclosing CFG");
        assert!(
            error.to_string().contains("matched no semantic"),
            "unexpected Scala nested callable selector for {body_call}: {error}"
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
            .unwrap_or_else(|| panic!("missing Scala {kind:?} procedure {name}"))
    };
    let top = named("topLevel", ProcedureKind::Function);
    let method = named("method", ProcedureKind::Method);
    let outer = named("outer", ProcedureKind::Function);
    let local = named("local", ProcedureKind::LocalFunction);
    let lambda = procedures
        .iter()
        .find(|procedure| procedure.kind() == ProcedureKind::Lambda)
        .expect("missing Scala lambda procedure");

    for procedure in [top, method, outer] {
        assert!(procedure.lexical_parent().is_none());
    }
    assert_eq!(local.lexical_parent(), Some(outer.id()));
    assert_eq!(lambda.lexical_parent(), Some(outer.id()));
    for procedure in [top, method, outer, local, lambda] {
        assert!(!procedure.properties().is_async);
        assert!(!procedure.properties().is_generator);
        assert_eq!(
            procedure.properties().invocation,
            ProcedureInvocationKind::Immediate
        );
        assert!(procedure.points().iter().any(|point| {
            point.events.iter().any(|event| {
                matches!(
                    event.effect,
                    SemanticEffect::ProcedureReturn { value: Some(_) }
                )
            })
        }));
    }

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn scala_local_class_members_are_methods_and_nested_defs_remain_local_functions() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/LocalClass.scala",
            r#"
                package conformance

                def outer(): Int = {
                  class LocalClass {
                    def member(): Int = {
                      def nested(): Int = nestedBody()
                      memberBody()
                    }
                  }
                  outerBody()
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "scala/LocalClass.scala");
    graph
        .bind(
            "outer_entry",
            PointSelector::new("def outer(): Int")
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
            "member_entry",
            PointSelector::new("def member(): Int")
                .procedure("member")
                .effect("entry"),
        )
        .bind(
            "member_invoke",
            PointSelector::new("memberBody()")
                .procedure("member")
                .effect("invoke"),
        )
        .bind(
            "nested_entry",
            PointSelector::new("def nested(): Int")
                .procedure("nested")
                .effect("entry"),
        )
        .bind(
            "nested_invoke",
            PointSelector::new("nestedBody()")
                .procedure("nested")
                .effect("invoke"),
        );
    for (entry, invoke) in [
        ("outer_entry", "outer_invoke"),
        ("member_entry", "member_invoke"),
        ("nested_entry", "nested_invoke"),
    ] {
        graph.assert_reachable(entry, invoke);
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
            .unwrap_or_else(|| panic!("missing Scala {kind:?} procedure {name}"))
    };
    let outer = named("outer", ProcedureKind::Function);
    let constructor = named("LocalClass", ProcedureKind::Constructor);
    let member = named("member", ProcedureKind::Method);
    let nested = named("nested", ProcedureKind::LocalFunction);
    assert_eq!(constructor.lexical_parent(), Some(outer.id()));
    assert_eq!(member.lexical_parent(), Some(outer.id()));
    assert_ne!(member.lexical_parent(), Some(constructor.id()));
    assert_eq!(nested.lexical_parent(), Some(member.id()));
    graph.assert_adjacency_symmetric();
}

#[test]
fn scala_if_loops_early_return_and_dead_syntax_have_exact_topology() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/Control.scala",
            r#"
                package conformance

                def choose(flag: Boolean): Int =
                  if flag then left() else right()

                def flow(whileKeep: Boolean, doKeep: Boolean, stop: Boolean): Int = {
                  while (whileKeep) { whileBody() }
                  do { doBody() } while (doKeep)
                  if stop then {
                    return early()
                    deadAfterReturn()
                  }
                  after()
                  9
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "scala/Control.scala");
    graph
        .bind(
            "choose_entry",
            PointSelector::new("def choose(flag: Boolean)")
                .procedure("choose")
                .effect("entry"),
        )
        .bind(
            "choose_decision",
            PointSelector::new("flag")
                .occurrence(1)
                .procedure("choose")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "left_entry",
            PointSelector::new("left()")
                .procedure("choose")
                .anchor_occurrence(0),
        )
        .bind(
            "right_entry",
            PointSelector::new("right()")
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
            "right_normal",
            PointSelector::new("right()")
                .procedure("choose")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "choose_return",
            PointSelector::new("if flag then left() else right()")
                .procedure("choose")
                .effect("procedure_return"),
        )
        .bind(
            "choose_normal_exit",
            PointSelector::new("def choose(flag: Boolean)")
                .procedure("choose")
                .effect("normal_exit"),
        )
        .bind(
            "flow_entry",
            PointSelector::new("def flow(whileKeep")
                .procedure("flow")
                .effect("entry"),
        )
        .bind(
            "while_entry",
            PointSelector::new("while (whileKeep) { whileBody() }")
                .procedure("flow")
                .anchor_occurrence(0),
        )
        .bind(
            "while_decision",
            PointSelector::new("whileKeep")
                .occurrence(1)
                .procedure("flow")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "while_body_block",
            PointSelector::new("{ whileBody() }")
                .procedure("flow")
                .anchor_occurrence(0),
        )
        .bind(
            "while_body_entry",
            PointSelector::new("whileBody()")
                .procedure("flow")
                .anchor_occurrence(0),
        )
        .bind(
            "while_body_normal",
            PointSelector::new("whileBody()")
                .procedure("flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "do_entry",
            PointSelector::new("do { doBody() } while (doKeep)")
                .procedure("flow")
                .anchor_occurrence(0),
        )
        .bind(
            "do_body_block",
            PointSelector::new("{ doBody() }")
                .procedure("flow")
                .anchor_occurrence(0),
        )
        .bind(
            "do_body_entry",
            PointSelector::new("doBody()")
                .procedure("flow")
                .anchor_occurrence(0),
        )
        .bind(
            "do_body_normal",
            PointSelector::new("doBody()")
                .procedure("flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "do_decision",
            PointSelector::new("doKeep")
                .occurrence(1)
                .procedure("flow")
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "stop_if",
            PointSelector::new(
                r#"if stop then {
                    return early()
                    deadAfterReturn()
                  }"#,
            )
            .procedure("flow")
            .anchor_occurrence(0),
        )
        .bind(
            "return_transfer",
            PointSelector::new("return early()")
                .procedure("flow")
                .effect("procedure_return"),
        )
        .bind(
            "flow_normal_exit",
            PointSelector::new("def flow(whileKeep")
                .procedure("flow")
                .effect("normal_exit"),
        )
        .bind(
            "dead_invoke",
            PointSelector::new("deadAfterReturn()")
                .procedure("flow")
                .effect("invoke"),
        )
        .bind(
            "after_invoke",
            PointSelector::new("after()")
                .procedure("flow")
                .effect("invoke"),
        );

    graph.assert_successors(
        "choose_decision",
        &[
            cfg_edge("left_entry", ControlEdgeKind::ConditionalTrue),
            cfg_edge("right_entry", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_predecessors(
        "choose_return",
        &[
            cfg_edge("left_normal", ControlEdgeKind::Normal),
            cfg_edge("right_normal", ControlEdgeKind::Normal),
        ],
    );
    graph.assert_successors(
        "choose_return",
        &[cfg_edge("choose_normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("choose_entry", "choose_return");

    graph.assert_successors(
        "while_entry",
        &[cfg_edge("while_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "while_decision",
        &[
            cfg_edge("while_body_block", ControlEdgeKind::ConditionalTrue),
            cfg_edge("do_entry", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "while_body_block",
        &[cfg_edge("while_body_entry", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "while_body_normal",
        &[cfg_edge("while_decision", ControlEdgeKind::LoopBack)],
    );
    graph.assert_successors(
        "do_entry",
        &[cfg_edge("do_body_block", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "do_body_block",
        &[cfg_edge("do_body_entry", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "do_body_normal",
        &[cfg_edge("do_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "do_decision",
        &[
            cfg_edge("do_body_block", ControlEdgeKind::LoopBack),
            cfg_edge("stop_if", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "return_transfer",
        &[cfg_edge("flow_normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("flow_entry", "after_invoke");
    graph.assert_unreachable("return_transfer", "after_invoke");
    graph.assert_unreachable("flow_entry", "dead_invoke");
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn scala_match_guards_are_ordered_and_unmatched_flow_is_exceptional() {
    let match_source = r#"value match {
                    case firstCandidate if firstGuard(firstCandidate) => first(firstCandidate)
                    case secondCandidate if secondGuard(secondCandidate) => second(secondCandidate)
                  }"#;
    let first_case_source = concat!(
        "case firstCandidate if firstGuard(firstCandidate) => first(firstCandidate)",
        "\n                    ",
    );
    let second_case_source = concat!(
        "case secondCandidate if secondGuard(secondCandidate) => second(secondCandidate)",
        "\n                  ",
    );
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/GuardedMatch.scala",
            r#"
                package conformance

                def guarded(value: Int): Int =
                  value match {
                    case firstCandidate if firstGuard(firstCandidate) => first(firstCandidate)
                    case secondCandidate if secondGuard(secondCandidate) => second(secondCandidate)
                  }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "scala/GuardedMatch.scala");
    graph
        .bind(
            "subject_entry",
            PointSelector::new(match_source)
                .procedure("guarded")
                .anchor_occurrence(0),
        )
        .bind(
            "match_return",
            PointSelector::new(match_source)
                .procedure("guarded")
                .effect("procedure_return"),
        )
        .bind(
            "dispatch",
            PointSelector::new(match_source)
                .procedure("guarded")
                .anchor_occurrence(1),
        )
        .bind(
            "unmatched",
            PointSelector::new(match_source)
                .procedure("guarded")
                .effect("throw"),
        )
        .bind(
            "first_pattern",
            PointSelector::new("firstCandidate")
                .occurrence(0)
                .procedure("guarded")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "second_pattern",
            PointSelector::new("secondCandidate")
                .occurrence(0)
                .procedure("guarded")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "first_guard_entry",
            PointSelector::new("firstGuard(firstCandidate)")
                .procedure("guarded")
                .anchor_occurrence(0),
        )
        .bind(
            "first_guard_decision",
            PointSelector::new("firstGuard(firstCandidate)")
                .procedure("guarded")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "second_guard_entry",
            PointSelector::new("secondGuard(secondCandidate)")
                .procedure("guarded")
                .anchor_occurrence(0),
        )
        .bind(
            "second_guard_decision",
            PointSelector::new("secondGuard(secondCandidate)")
                .procedure("guarded")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "first_body",
            PointSelector::new(first_case_source)
                .procedure("guarded")
                .anchor_occurrence(0),
        )
        .bind(
            "second_body",
            PointSelector::new(second_case_source)
                .procedure("guarded")
                .anchor_occurrence(0),
        )
        .bind(
            "first_normal",
            PointSelector::new("first(firstCandidate)")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "second_normal",
            PointSelector::new("second(secondCandidate)")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "exceptional_exit",
            PointSelector::new("def guarded(value: Int)")
                .procedure("guarded")
                .effect("exceptional_exit"),
        );

    graph.assert_successors(
        "subject_entry",
        &[cfg_edge("dispatch", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "dispatch",
        &[cfg_edge("first_pattern", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "first_pattern",
        &[
            cfg_edge("first_guard_entry", ControlEdgeKind::SwitchCase),
            cfg_edge("second_pattern", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "first_guard_decision",
        &[
            cfg_edge("first_body", ControlEdgeKind::ConditionalTrue),
            cfg_edge("second_pattern", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_predecessors(
        "second_pattern",
        &[
            cfg_edge("first_pattern", ControlEdgeKind::ConditionalFalse),
            cfg_edge("first_guard_decision", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "second_pattern",
        &[
            cfg_edge("second_guard_entry", ControlEdgeKind::SwitchCase),
            cfg_edge("unmatched", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "second_guard_decision",
        &[
            cfg_edge("second_body", ControlEdgeKind::ConditionalTrue),
            cfg_edge("unmatched", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_predecessors(
        "unmatched",
        &[
            cfg_edge("second_pattern", ControlEdgeKind::ConditionalFalse),
            cfg_edge("second_guard_decision", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "first_normal",
        &[cfg_edge("match_return", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "second_normal",
        &[cfg_edge("match_return", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "unmatched",
        &[cfg_edge("exceptional_exit", ControlEdgeKind::Exceptional)],
    );
    for pattern in ["first_pattern", "second_pattern"] {
        graph.assert_point_gap(pattern, SemanticCapability::Calls, SemanticGapKind::Unknown);
        graph.assert_point_gap(
            pattern,
            SemanticCapability::Values,
            SemanticGapKind::Unknown,
        );
        graph.assert_point_gap(
            pattern,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
        );
    }
    graph.assert_point_gap(
        "unmatched",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_unreachable("first_normal", "second_body");
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn scala_braced_try_catch_finally_specializes_normal_and_exceptional_cleanup() {
    let try_source = r#"try { work() }
                  catch { case error: Exception => recover(error) }
                  finally { cleanup() }"#;
    let catch_source = "catch { case error: Exception => recover(error) }";
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/BracedTry.scala",
            r#"
                package conformance

                def braced(): Int =
                  try { work() }
                  catch { case error: Exception => recover(error) }
                  finally { cleanup() }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "scala/BracedTry.scala");
    graph
        .bind(
            "work_normal",
            PointSelector::new("work()")
                .procedure("braced")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "work_exceptional",
            PointSelector::new("work()")
                .procedure("braced")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "try_body_exit",
            PointSelector::new("{ work() }")
                .procedure("braced")
                .anchor_occurrence(0),
        )
        .bind(
            "catch_dispatch",
            PointSelector::new(catch_source)
                .procedure("braced")
                .anchor_occurrence(0),
        )
        .bind(
            "catch_pattern",
            PointSelector::new("error: Exception")
                .occurrence(0)
                .procedure("braced")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "catch_body",
            PointSelector::new("case error: Exception => recover(error)")
                .procedure("braced")
                .anchor_occurrence(0),
        )
        .bind(
            "recover_normal",
            PointSelector::new("recover(error)")
                .procedure("braced")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "recover_exceptional",
            PointSelector::new("recover(error)")
                .procedure("braced")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Cleanup),
        )
        .bind(
            "catch_exit",
            PointSelector::new(catch_source)
                .procedure("braced")
                .anchor_occurrence(1),
        )
        .bind(
            "unmatched_catch",
            PointSelector::new(catch_source)
                .procedure("braced")
                .effect("throw"),
        )
        .bind(
            "normal_cleanup",
            PointSelector::new("{ cleanup() }")
                .procedure("braced")
                .anchor_occurrence(0),
        )
        .bind(
            "exceptional_cleanup",
            PointSelector::new("{ cleanup() }")
                .procedure("braced")
                .anchor_occurrence(1),
        )
        .bind(
            "exceptional_cleanup_relay",
            PointSelector::new("{ cleanup() }")
                .procedure("braced")
                .anchor_occurrence(2),
        )
        .bind(
            "exceptional_cleanup_call",
            PointSelector::new("cleanup()")
                .procedure("braced")
                .anchor_occurrence(0),
        )
        .bind(
            "normal_cleanup_call",
            PointSelector::new("cleanup()")
                .procedure("braced")
                .anchor_occurrence(4),
        )
        .bind(
            "exceptional_cleanup_normal",
            PointSelector::new("cleanup()")
                .procedure("braced")
                .effect("call_continuation")
                .anchor_occurrence(2),
        )
        .bind(
            "normal_cleanup_normal",
            PointSelector::new("cleanup()")
                .procedure("braced")
                .effect("call_continuation")
                .anchor_occurrence(6),
        )
        .bind(
            "normal_cleanup_exceptional",
            PointSelector::new("cleanup()")
                .procedure("braced")
                .effect("call_continuation")
                .anchor_occurrence(7),
        )
        .bind(
            "try_return",
            PointSelector::new(try_source)
                .procedure("braced")
                .effect("procedure_return"),
        )
        .bind(
            "exceptional_exit",
            PointSelector::new("def braced(): Int")
                .procedure("braced")
                .effect("exceptional_exit"),
        );

    graph.assert_successors(
        "work_normal",
        &[cfg_edge("try_body_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "work_exceptional",
        &[cfg_edge("catch_dispatch", ControlEdgeKind::Exceptional)],
    );
    graph.assert_successors(
        "catch_dispatch",
        &[cfg_edge("catch_pattern", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "catch_pattern",
        &[
            cfg_edge("catch_body", ControlEdgeKind::SwitchCase),
            cfg_edge("unmatched_catch", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "recover_normal",
        &[cfg_edge("catch_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "normal_cleanup",
        &[
            cfg_edge("try_body_exit", ControlEdgeKind::Cleanup),
            cfg_edge("catch_exit", ControlEdgeKind::Cleanup),
        ],
    );
    graph.assert_predecessors(
        "exceptional_cleanup",
        &[
            cfg_edge("recover_exceptional", ControlEdgeKind::Cleanup),
            cfg_edge("unmatched_catch", ControlEdgeKind::Cleanup),
        ],
    );
    graph.assert_successors(
        "normal_cleanup",
        &[cfg_edge("normal_cleanup_call", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "exceptional_cleanup",
        &[cfg_edge(
            "exceptional_cleanup_call",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_successors(
        "normal_cleanup_normal",
        &[cfg_edge("try_return", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "normal_cleanup_exceptional",
        &[cfg_edge("exceptional_exit", ControlEdgeKind::Exceptional)],
    );
    graph.assert_successors(
        "exceptional_cleanup_normal",
        &[cfg_edge(
            "exceptional_cleanup_relay",
            ControlEdgeKind::Normal,
        )],
    );
    graph.assert_successors(
        "exceptional_cleanup_relay",
        &[cfg_edge("exceptional_exit", ControlEdgeKind::Exceptional)],
    );
    graph.assert_point_gap(
        "catch_dispatch",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "catch_pattern",
        SemanticCapability::Calls,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "unmatched_catch",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn scala3_indented_try_catch_finally_specializes_both_cleanup_routes() {
    let catch_source = r#"catch
                    case error: Exception => indentedRecover(error)"#;
    let try_body_source = concat!("indentedWork()", "\n                  ");
    let finalizer_source = concat!(
        "cleanupStart\n                    indentedCleanup()",
        "\n            ",
    );
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/IndentedTry.scala",
            r#"
                package conformance

                def indented(): Int =
                  try
                    indentedWork()
                  catch
                    case error: Exception => indentedRecover(error)
                  finally
                    cleanupStart
                    indentedCleanup()
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "scala/IndentedTry.scala");
    graph
        .bind(
            "work_normal",
            PointSelector::new("indentedWork()")
                .procedure("indented")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "work_exceptional",
            PointSelector::new("indentedWork()")
                .procedure("indented")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "try_body_exit",
            PointSelector::new(try_body_source)
                .procedure("indented")
                .anchor_occurrence(0),
        )
        .bind(
            "catch_dispatch",
            PointSelector::new(catch_source)
                .procedure("indented")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::Normal)
                .anchor_occurrence(0),
        )
        .bind(
            "catch_pattern",
            PointSelector::new("error: Exception")
                .occurrence(0)
                .procedure("indented")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "catch_body",
            PointSelector::new("case error: Exception => indentedRecover(error)")
                .procedure("indented")
                .anchor_occurrence(0),
        )
        .bind(
            "recover_normal",
            PointSelector::new("indentedRecover(error)")
                .procedure("indented")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "recover_exceptional",
            PointSelector::new("indentedRecover(error)")
                .procedure("indented")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Cleanup),
        )
        .bind(
            "catch_exit",
            PointSelector::new(catch_source)
                .procedure("indented")
                .outgoing_kind(ControlEdgeKind::Cleanup)
                .anchor_occurrence(1),
        )
        .bind(
            "unmatched_catch",
            PointSelector::new(catch_source)
                .procedure("indented")
                .effect("throw"),
        )
        .bind(
            "normal_cleanup",
            PointSelector::new(finalizer_source)
                .procedure("indented")
                .anchor_occurrence(0),
        )
        .bind(
            "exceptional_cleanup",
            PointSelector::new(finalizer_source)
                .procedure("indented")
                .anchor_occurrence(1),
        )
        .bind(
            "try_return",
            PointSelector::new("try\n                    indentedWork()")
                .procedure("indented")
                .effect("procedure_return"),
        )
        .bind(
            "exceptional_exit",
            PointSelector::new("def indented(): Int")
                .procedure("indented")
                .effect("exceptional_exit"),
        );

    graph.assert_successors(
        "work_normal",
        &[cfg_edge("try_body_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "work_exceptional",
        &[cfg_edge("catch_dispatch", ControlEdgeKind::Exceptional)],
    );
    graph.assert_successors(
        "catch_dispatch",
        &[cfg_edge("catch_pattern", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "catch_pattern",
        &[
            cfg_edge("catch_body", ControlEdgeKind::SwitchCase),
            cfg_edge("unmatched_catch", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "recover_normal",
        &[cfg_edge("catch_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "normal_cleanup",
        &[
            cfg_edge("try_body_exit", ControlEdgeKind::Cleanup),
            cfg_edge("catch_exit", ControlEdgeKind::Cleanup),
        ],
    );
    graph.assert_predecessors(
        "exceptional_cleanup",
        &[
            cfg_edge("recover_exceptional", ControlEdgeKind::Cleanup),
            cfg_edge("unmatched_catch", ControlEdgeKind::Cleanup),
        ],
    );
    graph.assert_reachable("normal_cleanup", "try_return");
    graph.assert_reachable("exceptional_cleanup", "exceptional_exit");
    graph.assert_point_gap(
        "catch_dispatch",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "unmatched_catch",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn scala_for_enumerator_flow_retains_protocol_and_deferred_execution_gaps() {
    let for_source = "for value <- values yield transform(value)";
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/ForFlow.scala",
            r#"
                package conformance

                def enumerated(values: List[Int]): List[Int] =
                  for value <- values yield transform(value)
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "scala/ForFlow.scala");
    graph
        .bind(
            "for_entry",
            PointSelector::new(for_source)
                .procedure("enumerated")
                .anchor_occurrence(0),
        )
        .bind(
            "enumerator_decision",
            PointSelector::new("value <- values")
                .procedure("enumerated")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "body_entry",
            PointSelector::new("transform(value)")
                .procedure("enumerated")
                .anchor_occurrence(0),
        )
        .bind(
            "body_normal",
            PointSelector::new("transform(value)")
                .procedure("enumerated")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "for_return",
            PointSelector::new(for_source)
                .procedure("enumerated")
                .effect("procedure_return"),
        );

    graph.assert_successors(
        "for_entry",
        &[cfg_edge("enumerator_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "enumerator_decision",
        &[
            cfg_edge("body_entry", ControlEdgeKind::ConditionalTrue),
            cfg_edge("for_return", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "body_normal",
        &[cfg_edge("enumerator_decision", ControlEdgeKind::LoopBack)],
    );
    graph.assert_predecessors(
        "enumerator_decision",
        &[
            cfg_edge("for_entry", ControlEdgeKind::Normal),
            cfg_edge("body_normal", ControlEdgeKind::LoopBack),
        ],
    );
    for (capability, kind) in [
        (SemanticCapability::Calls, SemanticGapKind::Unsupported),
        (
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unsupported,
        ),
        (
            SemanticCapability::NormalControlFlow,
            SemanticGapKind::Unsupported,
        ),
        (
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
        ),
        (SemanticCapability::Values, SemanticGapKind::Unsupported),
    ] {
        graph.assert_point_gap("enumerator_decision", capability, kind);
    }
    let enumerated = procedure_named(&graph, "enumerated", ProcedureKind::Function);
    let deferred = enumerated
        .gaps()
        .iter()
        .find(|gap| {
            gap.capability == SemanticCapability::DeferredExecution
                && gap.detail.contains("desugared closures")
        })
        .expect("missing Scala for-comprehension deferred-execution gap");
    assert_deferred_effect_impacts(deferred, false, "desugared Scala closure execution");
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn scala_by_name_and_future_calls_report_callsite_scoped_execution_gaps() {
    let deferred_source = r#"
                package conformance

                def consume(value: => Int): Int = value

                def limitations(): Int = {
                  consume(delayed())
                  consume { firstDeferred(); secondDeferred() }
                  Future { spawned() }
                  done()
                  1
                }
            "#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("scala/Deferred.scala", deferred_source)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "scala/Deferred.scala");
    graph
        .bind(
            "consume_entry",
            PointSelector::new("def consume(value: => Int)")
                .procedure("consume")
                .effect("entry"),
        )
        .bind(
            "delayed_normal",
            PointSelector::new("delayed()")
                .procedure("limitations")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "strictness_invoke",
            PointSelector::new("consume(delayed())")
                .procedure("limitations")
                .effect("invoke"),
        )
        .bind(
            "strictness_normal",
            PointSelector::new("consume(delayed())")
                .procedure("limitations")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "structured_entry",
            PointSelector::new("consume { firstDeferred(); secondDeferred() }")
                .procedure("limitations")
                .anchor_occurrence(0),
        )
        .bind(
            "by_name_invoke",
            PointSelector::new("consume { firstDeferred(); secondDeferred() }")
                .procedure("limitations")
                .effect("invoke"),
        )
        .bind(
            "by_name_normal",
            PointSelector::new("consume { firstDeferred(); secondDeferred() }")
                .procedure("limitations")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "future_entry",
            PointSelector::new("Future { spawned() }")
                .procedure("limitations")
                .anchor_occurrence(0),
        )
        .bind(
            "future_invoke",
            PointSelector::new("Future { spawned() }")
                .procedure("limitations")
                .effect("invoke"),
        )
        .bind(
            "future_normal",
            PointSelector::new("Future { spawned() }")
                .procedure("limitations")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "done_entry",
            PointSelector::new("done()")
                .procedure("limitations")
                .anchor_occurrence(0),
        );

    graph.assert_point_gap(
        "consume_entry",
        SemanticCapability::DeferredExecution,
        SemanticGapKind::Unsupported,
    );
    let consume = graph
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
                == Some("consume")
        })
        .expect("missing Scala consume procedure");
    let by_name_callee_gap = consume
        .gaps()
        .iter()
        .find(|gap| gap.capability == SemanticCapability::DeferredExecution)
        .expect("missing Scala by-name callee gap");
    assert_deferred_effect_impacts(by_name_callee_gap, false, "by-name Scala callee");
    let limitations = graph
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
                == Some("limitations")
        })
        .expect("missing Scala limitations procedure");
    for (call_source, expected_capabilities, deferred_weakens_call_evaluation) in [
        (
            "consume(delayed())",
            &[SemanticCapability::DeferredExecution][..],
            false,
        ),
        (
            "consume { firstDeferred(); secondDeferred() }",
            &[SemanticCapability::DeferredExecution][..],
            true,
        ),
        (
            "Future { spawned() }",
            &[
                SemanticCapability::DeferredExecution,
                SemanticCapability::ConcurrentSpawn,
            ][..],
            true,
        ),
    ] {
        let call = limitations
            .call_sites()
            .iter()
            .find(|call| {
                let span = limitations
                    .source_mapping(call.source)
                    .expect("Scala call site must retain source mapping")
                    .locator
                    .anchor()
                    .span();
                deferred_source.get(span.start_byte() as usize..span.end_byte() as usize)
                    == Some(call_source)
            })
            .unwrap_or_else(|| panic!("missing Scala call site for {call_source}"));
        assert_eq!(
            call.arguments.len(),
            1,
            "each Scala source argument must remain one semantic actual for {call_source}"
        );
        for capability in expected_capabilities {
            let gap = limitations
                .gaps()
                .iter()
                .find(|gap| {
                    gap.point == call.point
                        && gap.subject == SemanticGapSubject::CallSite(call.id)
                        && gap.capability == *capability
                        && gap.kind == SemanticGapKind::Unknown
                })
                .unwrap_or_else(|| {
                    panic!("missing CallSite-scoped {capability:?} gap for {call_source}")
                });
            if *capability == SemanticCapability::DeferredExecution {
                assert_deferred_effect_impacts(gap, deferred_weakens_call_evaluation, call_source);
            }
        }
    }
    assert!(limitations.call_sites().iter().any(|call| {
        let span = limitations
            .source_mapping(call.source)
            .expect("Scala call site must retain source mapping")
            .locator
            .anchor()
            .span();
        deferred_source.get(span.start_byte() as usize..span.end_byte() as usize)
            == Some("delayed()")
    }));
    for nested in ["firstDeferred()", "secondDeferred()", "spawned()"] {
        assert!(
            limitations.call_sites().iter().all(|call| {
                let span = limitations
                    .source_mapping(call.source)
                    .expect("Scala call site must retain source mapping")
                    .locator
                    .anchor()
                    .span();
                deferred_source.get(span.start_byte() as usize..span.end_byte() as usize)
                    != Some(nested)
            }),
            "deferred Scala body {nested} was lowered as a synchronous call"
        );
    }
    graph.assert_successors(
        "delayed_normal",
        &[cfg_edge("strictness_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "strictness_normal",
        &[cfg_edge("structured_entry", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "by_name_normal",
        &[cfg_edge("future_entry", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "future_normal",
        &[cfg_edge("done_entry", ControlEdgeKind::Normal)],
    );
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn scala_generic_method_direct_call_conformance() {
    const CALLEE: &str = r#"
        package conformance

        final class GenericWorker {
          def identity[A](value: A): A = value
        }
    "#;
    const CALLER: &str = r#"
        package conformance

        object GenericCaller {
          def root(worker: GenericWorker): Int = worker.identity[Int](7)
        }
    "#;
    assert_return_partial_direct_call_conformance(DirectCallFixture {
        language: Language::Scala,
        dialect: SemanticLanguage::Standard(Language::Scala),
        callee_path: "scala/GenericWorker.scala",
        callee_source: CALLEE,
        callee_declaration: "def identity[A](value: A)",
        callee_name: "identity",
        caller_path: "scala/GenericCaller.scala",
        caller_source: CALLER,
        caller_declaration: "def root(worker: GenericWorker)",
        caller_name: "root",
        call: "worker.identity[Int](7)",
    });

    let project = InlineTestProject::with_language(Language::Scala)
        .file("scala/GenericWorker.scala", CALLEE)
        .file("scala/GenericCaller.scala", CALLER)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "scala/GenericCaller.scala");
    graph.bind(
        "generic_selection",
        PointSelector::new("worker.identity[Int]")
            .procedure("root")
            .effect("gap"),
    );
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
                == Some("root")
        })
        .expect("missing Scala generic-method caller");
    assert!(caller.gaps().iter().any(|gap| {
        matches!(gap.subject, SemanticGapSubject::Value(_))
            && gap.capability == SemanticCapability::ExceptionalControlFlow
            && gap.kind == SemanticGapKind::Unknown
    }));
    assert_eq!(caller.call_sites().len(), 1);
    let call = &caller.call_sites()[0];
    assert!(
        call.receiver.is_some(),
        "generic method application must retain its bound receiver"
    );
    let point = caller
        .point(call.point)
        .expect("generic method call point must remain available");
    assert!(point.events.iter().any(|event| {
        matches!(
            &event.effect,
            SemanticEffect::CallableReference { callable, .. }
                if callable.kind == CallableReferenceKind::BoundMethod
                    && callable.bound_receiver == call.receiver
        )
    }));
}

#[test]
fn scala_unqualified_identifier_reports_auto_application_uncertainty_without_a_callsite() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/Parameterless.scala",
            r#"
                package conformance

                def ping: Int = 7
                def root: Int = ping
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "scala/Parameterless.scala");
    graph
        .bind(
            "root_entry",
            PointSelector::new("def root: Int")
                .procedure("root")
                .effect("entry"),
        )
        .bind(
            "identifier",
            PointSelector::new("ping")
                .occurrence(1)
                .procedure("root")
                .effect("gap"),
        )
        .bind(
            "root_exit",
            PointSelector::new("def root: Int")
                .procedure("root")
                .effect("normal_exit"),
        );
    for capability in [
        SemanticCapability::Calls,
        SemanticCapability::ExceptionalControlFlow,
        SemanticCapability::CallableReferences,
    ] {
        graph.assert_point_gap("identifier", capability, SemanticGapKind::Unknown);
    }
    let root = graph
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
                == Some("root")
        })
        .expect("missing Scala parameterless root procedure");
    assert!(root.call_sites().is_empty());
    graph.assert_reachable("root_entry", "identifier");
    graph.assert_reachable("identifier", "root_exit");
    graph.assert_adjacency_symmetric();
}

#[test]
fn scala_interpolated_string_reports_interpolator_and_conversion_uncertainty() {
    const INTERPOLATION: &str = "s\"value=$value\"";
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/Interpolation.scala",
            r#"
                package conformance

                def render(value: Int): String = s"value=$value"
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "scala/Interpolation.scala");
    graph
        .bind(
            "render_entry",
            PointSelector::new("def render(value: Int)")
                .procedure("render")
                .effect("entry"),
        )
        .bind(
            "interpolation",
            PointSelector::new(INTERPOLATION)
                .procedure("render")
                .effect("gap"),
        )
        .bind(
            "render_exit",
            PointSelector::new("def render(value: Int)")
                .procedure("render")
                .effect("normal_exit"),
        );
    for capability in [
        SemanticCapability::Calls,
        SemanticCapability::ExceptionalControlFlow,
        SemanticCapability::Values,
    ] {
        graph.assert_point_gap("interpolation", capability, SemanticGapKind::Unknown);
    }
    let render = graph
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
                == Some("render")
        })
        .expect("missing Scala interpolation procedure");
    assert!(
        render.call_sites().is_empty(),
        "interpolation uncertainty must not fabricate a resolved call site"
    );
    graph.assert_reachable("render_entry", "interpolation");
    graph.assert_reachable("interpolation", "render_exit");
    graph.assert_adjacency_symmetric();
}

#[test]
fn scala_constructor_initializer_given_and_partial_function_procedures_are_distinct() {
    const SOURCE: &str = r#"
        package conformance

        class Box(value: Int) {
          constructorBody()
          val classLambda = () => classLambdaBody()
          def member(): Int = memberBody()
        }

        object Registry {
          initializerBody()
          val objectLambda = () => objectLambdaBody()
          val objectPartial: PartialFunction[Int, Int] = {
            case value => objectPartialBody(value)
          }
        }

        given label: String = "ready"
        given contextual(using value: Int): String = value.toString

        def partial(): PartialFunction[Int, Int] = {
          case value => closureBody(value)
        }
    "#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("scala/ProcedureKinds.scala", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "scala/ProcedureKinds.scala");
    graph
        .bind(
            "constructor_entry",
            PointSelector::new("class Box(value: Int)")
                .procedure("Box")
                .effect("entry"),
        )
        .bind(
            "constructor_exit",
            PointSelector::new("class Box(value: Int)")
                .procedure("Box")
                .effect("normal_exit"),
        )
        .bind(
            "initializer_entry",
            PointSelector::new("object Registry")
                .procedure("Registry")
                .effect("entry"),
        )
        .bind(
            "initializer_exit",
            PointSelector::new("object Registry")
                .procedure("Registry")
                .effect("normal_exit"),
        )
        .bind(
            "given_initializer_entry",
            PointSelector::new("given label: String")
                .procedure("label")
                .effect("entry"),
        )
        .bind(
            "given_initializer_exit",
            PointSelector::new("given label: String")
                .procedure("label")
                .effect("normal_exit"),
        )
        .bind(
            "given_function_entry",
            PointSelector::new("given contextual(using value: Int)")
                .procedure("contextual")
                .effect("entry"),
        )
        .bind(
            "given_function_exit",
            PointSelector::new("given contextual(using value: Int)")
                .procedure("contextual")
                .effect("normal_exit"),
        )
        .bind(
            "partial_entry",
            PointSelector::new("def partial(): PartialFunction")
                .procedure("partial")
                .effect("entry"),
        )
        .bind(
            "partial_exit",
            PointSelector::new("def partial(): PartialFunction")
                .procedure("partial")
                .effect("normal_exit"),
        )
        .bind(
            "closure_pattern",
            PointSelector::new("case value => closureBody(value)")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "closure_invoke",
            PointSelector::new("closureBody(value)").effect("invoke"),
        );

    for (entry, exit) in [
        ("constructor_entry", "constructor_exit"),
        ("initializer_entry", "initializer_exit"),
        ("given_initializer_entry", "given_initializer_exit"),
        ("given_function_entry", "given_function_exit"),
        ("partial_entry", "partial_exit"),
        ("closure_pattern", "closure_invoke"),
    ] {
        graph.assert_reachable(entry, exit);
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
            .unwrap_or_else(|| panic!("missing Scala {kind:?} procedure {name}"))
    };
    let constructor = named("Box", ProcedureKind::Constructor);
    let initializer = named("Registry", ProcedureKind::Initializer);
    let given_initializer = named("label", ProcedureKind::Initializer);
    let given_function = named("contextual", ProcedureKind::Function);
    let partial = named("partial", ProcedureKind::Function);
    let member = named("member", ProcedureKind::Method);
    let procedure_source = |procedure: &ProcedureSemantics| {
        let span = procedure.locator().anchor().span();
        SOURCE
            .get(span.start_byte() as usize..span.end_byte() as usize)
            .expect("Scala procedure locator must remain in the fixture")
    };
    let closure = procedures
        .iter()
        .find(|procedure| {
            procedure.kind() == ProcedureKind::Closure
                && procedure_source(procedure).contains("closureBody(value)")
        })
        .expect("missing Scala partial-function closure");
    let class_lambda = procedures
        .iter()
        .find(|procedure| {
            procedure.kind() == ProcedureKind::Lambda
                && procedure_source(procedure).contains("classLambdaBody()")
        })
        .expect("missing class-field lambda");
    let object_lambda = procedures
        .iter()
        .find(|procedure| {
            procedure.kind() == ProcedureKind::Lambda
                && procedure_source(procedure).contains("objectLambdaBody()")
        })
        .expect("missing object-field lambda");
    let object_partial = procedures
        .iter()
        .find(|procedure| {
            procedure.kind() == ProcedureKind::Closure
                && procedure_source(procedure).contains("objectPartialBody(value)")
        })
        .expect("missing object-field partial function");

    assert!(constructor.properties().is_synthetic);
    assert_eq!(
        constructor.properties().invocation,
        ProcedureInvocationKind::Immediate
    );
    assert!(initializer.properties().is_synthetic);
    assert_eq!(
        initializer.properties().invocation,
        ProcedureInvocationKind::Deferred
    );
    assert!(!given_initializer.properties().is_synthetic);
    assert_eq!(
        given_initializer.properties().invocation,
        ProcedureInvocationKind::Deferred
    );
    assert!(!given_function.properties().is_synthetic);
    assert_eq!(
        given_function.properties().invocation,
        ProcedureInvocationKind::Immediate
    );
    assert_eq!(closure.lexical_parent(), Some(partial.id()));
    assert_eq!(
        closure.properties().invocation,
        ProcedureInvocationKind::Immediate
    );
    assert_eq!(class_lambda.lexical_parent(), Some(constructor.id()));
    assert_eq!(object_lambda.lexical_parent(), Some(initializer.id()));
    assert_eq!(object_partial.lexical_parent(), Some(initializer.id()));
    assert_eq!(member.lexical_parent(), constructor.lexical_parent());
    assert_ne!(member.lexical_parent(), Some(constructor.id()));
    assert!(
        partial.call_sites().is_empty(),
        "the enclosing partial-function factory must not execute the case body"
    );
    assert_eq!(closure.call_sites().len(), 1);
    for deferred in [initializer, given_initializer] {
        let gap = deferred
            .gaps()
            .iter()
            .find(|gap| {
                gap.subject == SemanticGapSubject::Procedure
                    && gap.capability == SemanticCapability::DeferredExecution
            })
            .expect("missing demand-scheduled Scala procedure gap");
        assert_deferred_effect_impacts(gap, false, "demand-scheduled Scala procedure");
    }
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn scala_constructor_direct_call_conformance() {
    assert_return_partial_direct_call_conformance(DirectCallFixture {
        language: Language::Scala,
        dialect: SemanticLanguage::Standard(Language::Scala),
        callee_path: "scala/ConstructedBox.scala",
        callee_source: r#"
            package conformance

            final class ConstructedBox(value: Int)
        "#,
        callee_declaration: "final class ConstructedBox(value: Int)",
        callee_name: "ConstructedBox",
        caller_path: "scala/ConstructorCaller.scala",
        caller_source: r#"
            package conformance

            object ConstructorCaller {
              def root(): ConstructedBox = new ConstructedBox(7)
            }
        "#,
        caller_declaration: "def root(): ConstructedBox",
        caller_name: "root",
        call: "new ConstructedBox(7)",
    });
}

#[test]
fn scala_bodyless_templates_evaluate_parent_arguments_and_surface_parent_call_gaps() {
    const SOURCE: &str = r#"
        package conformance

        def classParentArgument(): Int = 1
        def objectParentArgument(): Int = 2
        class Base(value: Int)
        class Derived extends Base(classParentArgument())
        object Singleton extends Base(objectParentArgument())
    "#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("scala/BodylessParents.scala", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "scala/BodylessParents.scala");

    for (name, kind, declaration, argument_call) in [
        (
            "Derived",
            ProcedureKind::Constructor,
            "class Derived extends Base",
            "classParentArgument()",
        ),
        (
            "Singleton",
            ProcedureKind::Initializer,
            "object Singleton extends Base",
            "objectParentArgument()",
        ),
    ] {
        let entry_alias = format!("{name}_entry");
        let call_alias = format!("{name}_parent_call");
        let exit_alias = format!("{name}_exit");
        graph
            .bind(
                entry_alias.clone(),
                PointSelector::new(declaration)
                    .procedure(name)
                    .effect("entry"),
            )
            .bind(
                call_alias.clone(),
                PointSelector::new(argument_call)
                    .procedure(name)
                    .effect("invoke"),
            )
            .bind(
                exit_alias.clone(),
                PointSelector::new(declaration)
                    .procedure(name)
                    .effect("normal_exit"),
            );
        graph.assert_reachable(&entry_alias, &call_alias);
        graph.assert_reachable(&call_alias, &exit_alias);

        let procedure = procedure_named(&graph, name, kind);
        exact_call_site(procedure, SOURCE, argument_call);
        assert!(
            procedure.gaps().iter().all(|gap| {
                gap.capability != SemanticCapability::NormalControlFlow
                    || gap.kind != SemanticGapKind::Unsupported
            }),
            "bodyless template {name} must not be lowered as an unsupported expression",
        );

        let parent_call_gap = procedure
            .gaps()
            .iter()
            .find(|gap| {
                gap.point == procedure.entry_point()
                    && gap.subject == SemanticGapSubject::Point
                    && gap.capability == SemanticCapability::Calls
                    && gap.kind == SemanticGapKind::Unsupported
            })
            .unwrap_or_else(|| panic!("missing parent-initialization call gap for {name}"));
        for impact in [
            SemanticGapImpact::ValueFlow,
            SemanticGapImpact::ReturnTransfer,
            SemanticGapImpact::CallEvaluation,
            SemanticGapImpact::HeapRead,
            SemanticGapImpact::HeapWrite,
            SemanticGapImpact::Aliasing,
        ] {
            assert!(
                parent_call_gap.impacts.contains(impact),
                "parent-initialization call gap for {name} must affect {impact:?}",
            );
        }
    }
}

#[test]
fn scala_lambda_return_is_a_terminal_non_local_control_boundary() {
    let lambda_source = r#"(value: Int) => {
                    return escape(value)
                    deadInsideLambda()
                  }"#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/LambdaReturn.scala",
            r#"
                package conformance

                def outer(): Int = {
                  val lambda = (value: Int) => {
                    return escape(value)
                    deadInsideLambda()
                  }
                  afterLambdaCreation()
                  1
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "scala/LambdaReturn.scala");
    graph
        .bind(
            "lambda_entry",
            PointSelector::new(lambda_source).effect("entry"),
        )
        .bind(
            "escape_normal",
            PointSelector::new("escape(value)")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "non_local_return",
            PointSelector::new("return escape(value)").effect("gap"),
        )
        .bind(
            "lambda_normal_exit",
            PointSelector::new(lambda_source).effect("normal_exit"),
        )
        .bind(
            "lambda_exceptional_exit",
            PointSelector::new(lambda_source).effect("exceptional_exit"),
        )
        .bind(
            "dead_invoke",
            PointSelector::new("deadInsideLambda()").effect("invoke"),
        );

    graph.assert_successors(
        "escape_normal",
        &[cfg_edge("non_local_return", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "non_local_return",
        &[cfg_edge("escape_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors("non_local_return", &[]);
    graph.assert_point_gap(
        "non_local_return",
        SemanticCapability::NonLocalControl,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "non_local_return",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_reachable("lambda_entry", "non_local_return");
    graph.assert_unreachable("lambda_entry", "dead_invoke");
    graph.assert_unreachable("non_local_return", "lambda_normal_exit");
    graph.assert_unreachable("non_local_return", "lambda_exceptional_exit");
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn scala_partial_function_return_is_a_terminal_non_local_control_boundary() {
    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/PartialFunctionReturn.scala",
            r#"
                package conformance

                def partial(): PartialFunction[Int, Int] = {
                  case value =>
                    return escape(value)
                    deadInsideClosure()
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph =
        SemanticGraph::materialize(&project, &analyzer, "scala/PartialFunctionReturn.scala");
    graph
        .bind(
            "closure_pattern",
            PointSelector::new("case value =>\n                    return escape(value)")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "escape_normal",
            PointSelector::new("escape(value)")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "non_local_return",
            PointSelector::new("return escape(value)").effect("gap"),
        )
        .bind(
            "dead_invoke",
            PointSelector::new("deadInsideClosure()").effect("invoke"),
        );

    graph.assert_successors(
        "escape_normal",
        &[cfg_edge("non_local_return", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "non_local_return",
        &[cfg_edge("escape_normal", ControlEdgeKind::Normal)],
    );
    graph.assert_successors("non_local_return", &[]);
    graph.assert_point_gap(
        "non_local_return",
        SemanticCapability::NonLocalControl,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "non_local_return",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unsupported,
    );
    graph.assert_reachable("closure_pattern", "non_local_return");
    graph.assert_unreachable("closure_pattern", "dead_invoke");
    graph.assert_adjacency_symmetric();
}

#[test]
fn scala_nested_partial_functions_keep_the_inner_body_out_of_the_outer_closure() {
    const SOURCE: &str = r#"
        package conformance

        def nested(): PartialFunction[Int, Int] = {
          case outer =>
            val inner: PartialFunction[Int, Int] = {
              case inner => innerBody(inner)
            }
            outerBody(outer)
        }
    "#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("scala/NestedPartial.scala", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "scala/NestedPartial.scala");
    graph
        .bind(
            "outer_pattern",
            PointSelector::new("case outer =>").outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "outer_invoke",
            PointSelector::new("outerBody(outer)").effect("invoke"),
        )
        .bind(
            "inner_pattern",
            PointSelector::new("case inner => innerBody(inner)")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "inner_invoke",
            PointSelector::new("innerBody(inner)").effect("invoke"),
        );
    graph.assert_reachable("outer_pattern", "outer_invoke");
    graph.assert_reachable("inner_pattern", "inner_invoke");

    let closures = graph
        .artifact()
        .procedures()
        .iter()
        .filter(|procedure| procedure.kind() == ProcedureKind::Closure)
        .collect::<Vec<_>>();
    assert_eq!(closures.len(), 2);
    let procedure_source = |procedure: &ProcedureSemantics| {
        let span = procedure.locator().anchor().span();
        SOURCE
            .get(span.start_byte() as usize..span.end_byte() as usize)
            .expect("nested partial-function locator must remain in the fixture")
    };
    let outer = closures
        .iter()
        .copied()
        .find(|procedure| procedure_source(procedure).contains("case outer"))
        .expect("missing outer partial-function closure");
    let inner = closures
        .iter()
        .copied()
        .find(|procedure| {
            let source = procedure_source(procedure);
            source.contains("case inner") && !source.contains("case outer")
        })
        .expect("missing inner partial-function closure");
    assert_eq!(inner.lexical_parent(), Some(outer.id()));
    assert_eq!(outer.call_sites().len(), 1);
    assert_eq!(inner.call_sites().len(), 1);
    let call_source = |procedure: &ProcedureSemantics| {
        let call = &procedure.call_sites()[0];
        let span = procedure
            .source_mapping(call.source)
            .expect("nested partial-function call must retain source mapping")
            .locator
            .anchor()
            .span();
        SOURCE
            .get(span.start_byte() as usize..span.end_byte() as usize)
            .expect("nested partial-function call must remain in the fixture")
    };
    assert_eq!(call_source(outer), "outerBody(outer)");
    assert_eq!(call_source(inner), "innerBody(inner)");
    graph.assert_adjacency_symmetric();
}

#[test]
fn scala_curried_call_is_one_dispatch_matched_invoke() {
    const CALLEE: &str = r#"
        package conformance

        final class CurriedWorker {
          def combine(value: Int)(label: String): Int = value
        }
    "#;
    const CALLER: &str = r#"
        package conformance

        object CurriedCaller {
          def root(worker: CurriedWorker): Int = worker.combine(7)("seven")
        }
    "#;
    const CALL: &str = "worker.combine(7)(\"seven\")";

    assert_return_partial_direct_call_conformance(DirectCallFixture {
        language: Language::Scala,
        dialect: SemanticLanguage::Standard(Language::Scala),
        callee_path: "scala/CurriedWorker.scala",
        callee_source: CALLEE,
        callee_declaration: "def combine(value: Int)(label: String)",
        callee_name: "combine",
        caller_path: "scala/CurriedCaller.scala",
        caller_source: CALLER,
        caller_declaration: "def root(worker: CurriedWorker)",
        caller_name: "root",
        call: CALL,
    });

    let project = InlineTestProject::with_language(Language::Scala)
        .file("scala/CurriedWorker.scala", CALLEE)
        .file("scala/CurriedCaller.scala", CALLER)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "scala/CurriedCaller.scala");
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
                == Some("root")
        })
        .expect("missing Scala curried caller procedure");
    assert_eq!(caller.call_sites().len(), 1);
    let call = &caller.call_sites()[0];
    let span = caller
        .source_mapping(call.source)
        .expect("curried call site must retain source mapping")
        .locator
        .anchor()
        .span();
    assert_eq!(
        CALLER.get(span.start_byte() as usize..span.end_byte() as usize),
        Some(CALL)
    );
}

#[test]
fn scala_curried_constructor_is_one_call_and_evaluates_every_argument_list() {
    const CALL: &str = "new CurriedBox(firstArgument())(secondArgument())";
    const SOURCE: &str = r#"
        package conformance

        final class CurriedBox(value: Int)(label: String)

        def firstArgument(): Int = 7
        def secondArgument(): String = "seven"

        def root(): CurriedBox =
          new CurriedBox(firstArgument())(secondArgument())
    "#;
    let project = InlineTestProject::with_language(Language::Scala)
        .file("scala/CurriedConstructor.scala", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph =
        SemanticGraph::materialize(&project, &analyzer, "scala/CurriedConstructor.scala");
    graph
        .bind(
            "first_normal",
            PointSelector::new("firstArgument()")
                .procedure("root")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "second_entry",
            PointSelector::new("secondArgument()")
                .occurrence(1)
                .procedure("root")
                .anchor_occurrence(0),
        )
        .bind(
            "second_normal",
            PointSelector::new("secondArgument()")
                .procedure("root")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "constructor_invoke",
            PointSelector::new(CALL).procedure("root").effect("invoke"),
        );
    graph.assert_successors(
        "first_normal",
        &[cfg_edge("second_entry", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("second_entry", "second_normal");
    graph.assert_successors(
        "second_normal",
        &[cfg_edge("constructor_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "constructor_invoke",
        &[cfg_edge("second_normal", ControlEdgeKind::Normal)],
    );

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
                == Some("root")
        })
        .expect("missing Scala curried-constructor caller");
    assert_eq!(
        caller.call_sites().len(),
        3,
        "two argument calls and one constructor call must be emitted"
    );
    let constructor_calls = caller
        .call_sites()
        .iter()
        .filter(|call| {
            let span = caller
                .source_mapping(call.source)
                .expect("Scala call site must retain source mapping")
                .locator
                .anchor()
                .span();
            SOURCE.get(span.start_byte() as usize..span.end_byte() as usize) == Some(CALL)
        })
        .collect::<Vec<_>>();
    assert_eq!(constructor_calls.len(), 1);
    let constructor = constructor_calls[0];
    assert_eq!(constructor.arguments.len(), 2);
    let point = caller
        .point(constructor.point)
        .expect("constructor call point must remain available");
    assert!(point.events.iter().any(|event| {
        matches!(
            &event.effect,
            SemanticEffect::CallableReference { callable, .. }
                if callable.kind == CallableReferenceKind::Constructor
        )
    }));
    assert!(caller.call_sites().iter().all(|call| {
        let span = caller
            .source_mapping(call.source)
            .expect("Scala call site must retain source mapping")
            .locator
            .anchor()
            .span();
        SOURCE.get(span.start_byte() as usize..span.end_byte() as usize)
            != Some("new CurriedBox(firstArgument())")
    }));
    graph.assert_adjacency_symmetric();
}

#[test]
fn scala_infix_right_associative_and_postfix_calls_have_icfg_and_source_order() {
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::Scala,
        dialect: SemanticLanguage::Standard(Language::Scala),
        callee_path: "scala/InfixTypes.scala",
        callee_source: r#"
            package conformance
            final class Right
            final class Left { def combine(right: Right): Int = 1 }
        "#,
        callee_declaration: "def combine(right: Right)",
        callee_name: "combine",
        caller_path: "scala/InfixCaller.scala",
        caller_source: r#"
            package conformance
            object InfixCaller {
              def root(left: Left, right: Right): Int = left combine right
            }
        "#,
        caller_declaration: "def root(left: Left, right: Right)",
        caller_name: "root",
        call: "left combine right",
    });
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::Scala,
        dialect: SemanticLanguage::Standard(Language::Scala),
        callee_path: "scala/ColonTypes.scala",
        callee_source: r#"
            package conformance
            final class Head
            final class Tail { def ::(head: Head): Int = 2 }
        "#,
        callee_declaration: "def ::(head: Head)",
        callee_name: "::",
        caller_path: "scala/ColonCaller.scala",
        caller_source: r#"
            package conformance
            object ColonCaller {
              def root(head: Head, tail: Tail): Int = head :: tail
            }
        "#,
        caller_declaration: "def root(head: Head, tail: Tail)",
        caller_name: "root",
        call: "head :: tail",
    });
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::Scala,
        dialect: SemanticLanguage::Standard(Language::Scala),
        callee_path: "scala/PostfixBox.scala",
        callee_source: r#"
            package conformance
            final class PostfixBox { def ! : Boolean = true }
        "#,
        callee_declaration: "def ! : Boolean",
        callee_name: "!",
        caller_path: "scala/PostfixCaller.scala",
        caller_source: r#"
            package conformance
            object PostfixCaller {
              def root(box: PostfixBox): Boolean = box !
            }
        "#,
        caller_declaration: "def root(box: PostfixBox)",
        caller_name: "root",
        call: "box !",
    });

    let project = InlineTestProject::with_language(Language::Scala)
        .file(
            "scala/OperatorOrder.scala",
            r#"
                package conformance

                final class Right
                final class Left { def combine(right: Right): Int = 1 }
                final class Head
                final class Tail { def ::(head: Head): Int = 2 }
                final class PostfixBox { def ! : Boolean = true }

                object OperatorOrder {
                  def infix(leftOperand: Left, rightOperand: Right): Int =
                    leftOperand combine rightOperand

                  def colon(headOperand: Head, tailOperand: Tail): Int =
                    headOperand :: tailOperand

                  def postfix(boxOperand: PostfixBox): Boolean = boxOperand !
                }
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "scala/OperatorOrder.scala");
    graph
        .bind(
            "infix_entry",
            PointSelector::new("leftOperand combine rightOperand")
                .procedure("infix")
                .anchor_occurrence(0),
        )
        .bind(
            "infix_left",
            PointSelector::new("leftOperand")
                .occurrence(1)
                .procedure("infix"),
        )
        .bind(
            "infix_right",
            PointSelector::new("rightOperand")
                .occurrence(1)
                .procedure("infix"),
        )
        .bind(
            "infix_invoke",
            PointSelector::new("leftOperand combine rightOperand")
                .procedure("infix")
                .effect("invoke"),
        )
        .bind(
            "colon_entry",
            PointSelector::new("headOperand :: tailOperand")
                .procedure("colon")
                .anchor_occurrence(0),
        )
        .bind(
            "colon_left",
            PointSelector::new("headOperand")
                .occurrence(1)
                .procedure("colon"),
        )
        .bind(
            "colon_right",
            PointSelector::new("tailOperand")
                .occurrence(1)
                .procedure("colon"),
        )
        .bind(
            "colon_invoke",
            PointSelector::new("headOperand :: tailOperand")
                .procedure("colon")
                .effect("invoke"),
        )
        .bind(
            "postfix_entry",
            PointSelector::new("boxOperand !")
                .procedure("postfix")
                .anchor_occurrence(0),
        )
        .bind(
            "postfix_receiver",
            PointSelector::new("boxOperand")
                .occurrence(1)
                .procedure("postfix"),
        )
        .bind(
            "postfix_invoke",
            PointSelector::new("boxOperand !")
                .procedure("postfix")
                .effect("invoke"),
        );

    graph.assert_successors(
        "infix_entry",
        &[cfg_edge("infix_left", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "infix_left",
        &[cfg_edge("infix_right", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "infix_right",
        &[cfg_edge("infix_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "colon_entry",
        &[cfg_edge("colon_left", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "colon_left",
        &[cfg_edge("colon_right", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "colon_right",
        &[cfg_edge("colon_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "postfix_entry",
        &[cfg_edge("postfix_receiver", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "postfix_receiver",
        &[cfg_edge("postfix_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn ruby_cross_file_singleton_call_conformance() {
    assert_direct_call_conformance(DirectCallFixture {
        language: Language::Ruby,
        dialect: SemanticLanguage::Standard(Language::Ruby),
        callee_path: "ruby/ruby_library.rb",
        callee_source: r#"
            class RubyLibrary
              def self.ruby_leaf
                7
              end
            end
        "#,
        callee_declaration: "def self.ruby_leaf",
        callee_name: "ruby_leaf",
        caller_path: "ruby/ruby_caller.rb",
        caller_source: r#"
            require_relative "ruby_library"

            class RubyCaller
              def self.ruby_root
                RubyLibrary.ruby_leaf()
              end
            end
        "#,
        caller_declaration: "def self.ruby_root",
        caller_name: "ruby_root",
        call: "RubyLibrary.ruby_leaf()",
    });
}

#[test]
fn ruby_same_class_bare_call_uses_the_shared_icfg() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "ruby/same_class.rb",
            r#"
                class SameClass
                  def leaf
                    7
                  end

                  def root
                    if leaf
                      1
                    else
                      0
                    end
                  end
                end
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = IcfgGraph::materialize(
        &project,
        &analyzer,
        "ruby/same_class.rb",
        PointSelector::new("def root")
            .procedure("root")
            .effect("entry"),
    );
    graph
        .bind_call(
            "bare_call",
            "ruby/same_class.rb",
            PointSelector::new("leaf")
                .occurrence(1)
                .procedure("root")
                .effect("invoke"),
        )
        .bind_node(
            "caller_entry",
            "ruby/same_class.rb",
            PointSelector::new("def root")
                .procedure("root")
                .effect("entry"),
            root(),
        )
        .bind_node(
            "invoke",
            "ruby/same_class.rb",
            PointSelector::new("leaf")
                .occurrence(1)
                .procedure("root")
                .effect("invoke"),
            root(),
        )
        .bind_node(
            "callee_entry",
            "ruby/same_class.rb",
            PointSelector::new("def leaf")
                .procedure("leaf")
                .effect("entry"),
            ["bare_call"],
        )
        .bind_node(
            "callee_normal_exit",
            "ruby/same_class.rb",
            PointSelector::new("def leaf")
                .procedure("leaf")
                .effect("normal_exit"),
            ["bare_call"],
        )
        .bind_node(
            "normal_continuation",
            "ruby/same_class.rb",
            PointSelector::new("leaf")
                .occurrence(1)
                .procedure("root")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
            root(),
        );

    graph.assert_outcome(IcfgOutcomeKind::Unproven);
    graph.assert_boundary(
        "invoke",
        ExpectedIcfgBoundary::new(ExpectedIcfgBoundaryKind::DispatchUnresolved)
            .originating_call("bare_call"),
    );
    graph.assert_successors(
        "invoke",
        &[icfg_edge("callee_entry", IcfgEdgeKind::Call).originating_call("bare_call")],
    );
    graph.assert_predecessors(
        "callee_entry",
        &[icfg_edge("invoke", IcfgEdgeKind::Call).originating_call("bare_call")],
    );
    graph.assert_successors(
        "callee_normal_exit",
        &[icfg_edge("normal_continuation", IcfgEdgeKind::NormalReturn)
            .originating_call("bare_call")],
    );
    graph.assert_predecessors(
        "normal_continuation",
        &[icfg_edge("callee_normal_exit", IcfgEdgeKind::NormalReturn)
            .originating_call("bare_call")],
    );
    graph.assert_reachable("caller_entry", "normal_continuation");
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("IcfgNodeId"));
    assert!(!rendered.contains("IcfgEdgeId"));
}

#[test]
fn ruby_methods_singletons_lambdas_and_attached_blocks_are_separate() {
    const SOURCE: &str = r#"
        def top_level
          top_body()
        end

        class Worker
          def initialize
            constructor_body()
          end

          def step
            method_body()
          end

          def self.build
            singleton_body()
          end

          class << self
            def create
              singleton_class_body()
            end
          end
        end

        def outer(items)
          callback = ->(value) { lambda_body(value) }
          items.each do |item|
            block_body(item)
          end
          outer_body()
        end
    "#;
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("ruby/callables.rb", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "ruby/callables.rb");

    for (alias, declaration, procedure, body_call) in [
        ("top", "def top_level", "top_level", "top_body()"),
        (
            "constructor",
            "def initialize",
            "initialize",
            "constructor_body()",
        ),
        ("method", "def step", "step", "method_body()"),
        ("singleton", "def self.build", "build", "singleton_body()"),
        (
            "singleton_class",
            "def create",
            "create",
            "singleton_class_body()",
        ),
        ("outer", "def outer(items)", "outer", "outer_body()"),
    ] {
        graph
            .bind(
                format!("{alias}_entry"),
                PointSelector::new(declaration)
                    .procedure(procedure)
                    .effect("entry"),
            )
            .bind(
                format!("{alias}_body"),
                PointSelector::new(body_call)
                    .procedure(procedure)
                    .effect("invoke"),
            );
        graph.assert_reachable(&format!("{alias}_entry"), &format!("{alias}_body"));
    }
    graph
        .bind(
            "lambda_entry",
            PointSelector::new("->(value) { lambda_body(value) }").effect("entry"),
        )
        .bind(
            "lambda_body",
            PointSelector::new("lambda_body(value)").effect("invoke"),
        )
        .bind(
            "block_entry",
            PointSelector::new("do |item|\n            block_body(item)\n          end")
                .effect("entry"),
        )
        .bind(
            "block_body",
            PointSelector::new("block_body(item)").effect("invoke"),
        );
    graph.assert_reachable("lambda_entry", "lambda_body");
    graph.assert_reachable("block_entry", "block_body");

    let top = procedure_named(&graph, "top_level", ProcedureKind::Method);
    let constructor = procedure_named(&graph, "initialize", ProcedureKind::Constructor);
    let method = procedure_named(&graph, "step", ProcedureKind::Method);
    let singleton = procedure_named(&graph, "build", ProcedureKind::Method);
    let singleton_class = procedure_named(&graph, "create", ProcedureKind::Method);
    let outer = procedure_named(&graph, "outer", ProcedureKind::Method);
    let lambdas = graph
        .artifact()
        .procedures()
        .iter()
        .filter(|procedure| procedure.kind() == ProcedureKind::Lambda)
        .collect::<Vec<_>>();
    let closures = graph
        .artifact()
        .procedures()
        .iter()
        .filter(|procedure| procedure.kind() == ProcedureKind::Closure)
        .collect::<Vec<_>>();
    assert_eq!(lambdas.len(), 1, "arrow syntax must publish one lambda");
    assert_eq!(
        closures.len(),
        1,
        "the attached block must publish one closure"
    );
    let lambda = lambdas[0];
    let closure = closures[0];

    for procedure in [top, constructor, method, singleton, singleton_class, outer] {
        assert!(procedure.lexical_parent().is_none());
        assert_eq!(
            procedure.properties().invocation,
            ProcedureInvocationKind::Immediate
        );
    }
    assert!(!constructor.properties().is_static);
    assert!(!method.properties().is_static);
    assert!(singleton.properties().is_static);
    assert!(singleton_class.properties().is_static);
    assert_eq!(lambda.lexical_parent(), Some(outer.id()));
    assert_eq!(closure.lexical_parent(), Some(outer.id()));
    assert_eq!(
        lambda.properties().invocation,
        ProcedureInvocationKind::Immediate
    );
    assert_eq!(
        closure.properties().invocation,
        ProcedureInvocationKind::Immediate
    );

    for nested in ["lambda_body(value)", "block_body(item)"] {
        assert_no_exact_call_site(outer, SOURCE, nested);
    }
    assert_call_site_gap(
        outer,
        SOURCE,
        "items.each do |item|\n            block_body(item)\n          end",
        SemanticCapability::DeferredExecution,
        SemanticGapKind::Unknown,
    );
    let each_call = exact_call_site(
        outer,
        SOURCE,
        "items.each do |item|\n            block_body(item)\n          end",
    );
    let deferred = outer
        .gaps()
        .iter()
        .find(|gap| {
            gap.subject == SemanticGapSubject::CallSite(each_call.id)
                && gap.capability == SemanticCapability::DeferredExecution
        })
        .expect("attached block must retain a deferred-execution gap");
    assert_deferred_effect_impacts(deferred, false, "attached Ruby block");
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn ruby_parameters_assigned_locals_and_block_parameters_are_not_bare_calls() {
    const SOURCE: &str = r#"
        class Shadowing
          def helper
            1
          end

          def run(parameter, items)
            assigned = helper()
            parameter
            assigned
            items.each do |item|
              item
            end
            helper
          end
        end
    "#;
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("ruby/shadowing.rb", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "ruby/shadowing.rb");
    let run = procedure_named(&graph, "run", ProcedureKind::Method);

    exact_call_site(run, SOURCE, "helper()");
    exact_call_site(
        run,
        SOURCE,
        "items.each do |item|\n              item\n            end",
    );
    exact_call_site(run, SOURCE, "helper");
    for local_read in ["parameter", "assigned"] {
        assert_no_exact_call_site(run, SOURCE, local_read);
    }
    let closure = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| procedure.kind() == ProcedureKind::Closure)
        .expect("attached each block must publish a closure");
    assert_no_exact_call_site(closure, SOURCE, "item");
    graph.assert_adjacency_symmetric();
}

#[test]
fn ruby_local_bindings_follow_parser_encounter_order_across_closures() {
    const SOURCE: &str = r#"
        class ParseOrder
          def before_assignment
            target
            target = seed()
          end

          def after_assignment
            target = seed()
            target
          end

          def closure_order
            before_capture = -> { future_binding }
            future_binding = seed()
            existing_binding = seed()
            after_capture = -> { existing_binding }
            self_capture = -> { self_capture }
            reassigned_capture = -> do
              existing_binding
              existing_binding = refresh()
              existing_binding
            end
          end
        end
    "#;
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("ruby/parse_order.rb", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let graph = SemanticGraph::materialize(&project, &analyzer, "ruby/parse_order.rb");

    let before_assignment = procedure_named(&graph, "before_assignment", ProcedureKind::Method);
    exact_call_site(before_assignment, SOURCE, "target");
    exact_call_site(before_assignment, SOURCE, "seed()");

    let after_assignment = procedure_named(&graph, "after_assignment", ProcedureKind::Method);
    exact_call_site(after_assignment, SOURCE, "seed()");
    assert_no_exact_call_site(after_assignment, SOURCE, "target");

    let before_capture = procedure_named(&graph, "before_capture", ProcedureKind::Lambda);
    exact_call_site(before_capture, SOURCE, "future_binding");

    let after_capture = procedure_named(&graph, "after_capture", ProcedureKind::Lambda);
    assert_no_exact_call_site(after_capture, SOURCE, "existing_binding");

    let self_capture = procedure_named(&graph, "self_capture", ProcedureKind::Lambda);
    assert_no_exact_call_site(self_capture, SOURCE, "self_capture");

    let reassigned_capture = procedure_named(&graph, "reassigned_capture", ProcedureKind::Lambda);
    assert_no_exact_call_site(reassigned_capture, SOURCE, "existing_binding");
    exact_call_site(reassigned_capture, SOURCE, "refresh()");
    graph.assert_adjacency_symmetric();
}

#[test]
fn ruby_captured_implicit_default_and_pattern_bindings_are_not_bare_calls() {
    const SOURCE: &str = r#"
        class Lexical
          def leaf
            true
          end

          def run(parameter, items, optional = default_value())
            captured = -> { parameter }
            items.map { _1.transform }
            if leaf
              first()
            elsif fallback
              second()
            else
              third()
            end
            case items
            in {name:}
              name
            else
              nil
            end
          end
        end
    "#;
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("ruby/lexical_bindings.rb", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "ruby/lexical_bindings.rb");
    graph
        .bind(
            "run_entry",
            PointSelector::new("def run(parameter, items, optional = default_value())")
                .procedure("run")
                .effect("entry"),
        )
        .bind(
            "leaf_normal",
            PointSelector::new("leaf")
                .occurrence(1)
                .procedure("run")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "leaf_decision",
            PointSelector::new("leaf")
                .occurrence(1)
                .procedure("run")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "first_statement",
            PointSelector::new("first()")
                .procedure("run")
                .anchor_occurrence(0),
        )
        .bind(
            "elsif_entry",
            PointSelector::new("elsif fallback")
                .procedure("run")
                .anchor_occurrence(0),
        )
        .bind(
            "fallback_invoke",
            PointSelector::new("fallback")
                .procedure("run")
                .effect("invoke"),
        )
        .bind(
            "fallback_normal",
            PointSelector::new("fallback")
                .procedure("run")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "fallback_decision",
            PointSelector::new("fallback")
                .procedure("run")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "second_statement",
            PointSelector::new("second()")
                .procedure("run")
                .anchor_occurrence(0),
        )
        .bind(
            "third_statement",
            PointSelector::new("third()")
                .procedure("run")
                .anchor_occurrence(0),
        );

    graph.assert_point_gap(
        "run_entry",
        SemanticCapability::Calls,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "run_entry",
        SemanticCapability::Values,
        SemanticGapKind::Unknown,
    );
    graph.assert_point_gap(
        "run_entry",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_successors(
        "leaf_normal",
        &[cfg_edge("leaf_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "leaf_decision",
        &[
            cfg_edge("first_statement", ControlEdgeKind::ConditionalTrue),
            cfg_edge("elsif_entry", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "elsif_entry",
        &[cfg_edge("fallback_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "fallback_normal",
        &[cfg_edge("fallback_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "fallback_decision",
        &[
            cfg_edge("second_statement", ControlEdgeKind::ConditionalTrue),
            cfg_edge("third_statement", ControlEdgeKind::ConditionalFalse),
        ],
    );

    let run = procedure_named(&graph, "run", ProcedureKind::Method);
    for non_call in ["default_value()", "parameter", "_1", "name"] {
        assert_no_exact_call_site(run, SOURCE, non_call);
    }
    for nested in ["parameter", "_1.transform"] {
        assert_no_exact_call_site(run, SOURCE, nested);
    }
    let captured = procedure_named(&graph, "captured", ProcedureKind::Lambda);
    assert_no_exact_call_site(captured, SOURCE, "parameter");
    let numbered = graph
        .artifact()
        .procedures()
        .iter()
        .find(|procedure| procedure.kind() == ProcedureKind::Closure)
        .expect("map block must publish a closure");
    assert_no_exact_call_site(numbered, SOURCE, "_1");
    exact_call_site(numbered, SOURCE, "_1.transform");
    graph.assert_adjacency_symmetric();
}

#[test]
fn ruby_implicit_returns_preserve_branch_and_case_values() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "ruby/implicit_returns.rb",
            r#"
                def choose(flag)
                  if flag
                    left()
                  else
                    right()
                  end
                end

                def classify(value)
                  case value
                  when 0
                    zero()
                  when 1, 2
                    small()
                  else
                    other()
                  end
                end
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "ruby/implicit_returns.rb");
    graph
        .bind(
            "choose_entry",
            PointSelector::new("def choose(flag)")
                .procedure("choose")
                .effect("entry"),
        )
        .bind(
            "choose_decision",
            PointSelector::new("flag")
                .occurrence(1)
                .procedure("choose")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "left_entry",
            PointSelector::new("left()")
                .procedure("choose")
                .anchor_occurrence(0),
        )
        .bind(
            "right_entry",
            PointSelector::new("right()")
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
            "right_normal",
            PointSelector::new("right()")
                .procedure("choose")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "choose_return",
            PointSelector::new("if flag")
                .procedure("choose")
                .effect("procedure_return"),
        )
        .bind(
            "choose_normal_exit",
            PointSelector::new("def choose(flag)")
                .procedure("choose")
                .effect("normal_exit"),
        )
        .bind(
            "classify_entry",
            PointSelector::new("def classify(value)")
                .procedure("classify")
                .effect("entry"),
        )
        .bind(
            "zero_normal",
            PointSelector::new("zero()")
                .procedure("classify")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "small_normal",
            PointSelector::new("small()")
                .procedure("classify")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "other_normal",
            PointSelector::new("other()")
                .procedure("classify")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "classify_return",
            PointSelector::new("case value")
                .procedure("classify")
                .effect("procedure_return"),
        )
        .bind(
            "classify_normal_exit",
            PointSelector::new("def classify(value)")
                .procedure("classify")
                .effect("normal_exit"),
        );

    graph.assert_successors(
        "choose_decision",
        &[
            cfg_edge("left_entry", ControlEdgeKind::ConditionalTrue),
            cfg_edge("right_entry", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_predecessors(
        "choose_return",
        &[
            cfg_edge("left_normal", ControlEdgeKind::Normal),
            cfg_edge("right_normal", ControlEdgeKind::Normal),
        ],
    );
    graph.assert_successors(
        "choose_return",
        &[cfg_edge("choose_normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("choose_entry", "choose_return");

    graph.assert_predecessors(
        "classify_return",
        &[
            cfg_edge("zero_normal", ControlEdgeKind::Normal),
            cfg_edge("small_normal", ControlEdgeKind::Normal),
            cfg_edge("other_normal", ControlEdgeKind::Normal),
        ],
    );
    graph.assert_successors(
        "classify_return",
        &[cfg_edge("classify_normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("classify_entry", "zero_normal");
    graph.assert_reachable("classify_entry", "small_normal");
    graph.assert_reachable("classify_entry", "other_normal");
    graph.assert_unreachable("zero_normal", "small_normal");
    graph.assert_unreachable("small_normal", "other_normal");
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn ruby_loops_abrupt_completions_and_dead_regions_have_exact_topology() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "ruby/loop_flow.rb",
            r#"
                def flow(keep, skip, repeat, stop)
                  while keep
                    if skip
                      next next_value()
                    end
                    if repeat
                      redo
                    end
                    break break_value() if stop
                    body()
                  end
                  after_loop()
                  return final_value()
                  dead_after_return()
                end
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "ruby/loop_flow.rb");
    graph
        .bind(
            "entry",
            PointSelector::new("def flow(keep, skip, repeat, stop)")
                .procedure("flow")
                .effect("entry"),
        )
        .bind(
            "while_condition_entry",
            PointSelector::new("keep")
                .occurrence(1)
                .procedure("flow")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "while_decision",
            PointSelector::new("keep")
                .occurrence(1)
                .procedure("flow")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "loop_body",
            PointSelector::new(
                r#"if skip
                      next next_value()
                    end
                    if repeat
                      redo
                    end
                    break break_value() if stop
                    body()"#,
            )
            .procedure("flow")
            .anchor_occurrence(0),
        )
        .bind(
            "next_value_normal",
            PointSelector::new("next_value()")
                .procedure("flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "next_transfer",
            PointSelector::new("next next_value()")
                .procedure("flow")
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "redo_transfer",
            PointSelector::new("redo")
                .procedure("flow")
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "break_value_normal",
            PointSelector::new("break_value()")
                .procedure("flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "break_transfer",
            PointSelector::new("break break_value()")
                .procedure("flow")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "body_normal",
            PointSelector::new("body()")
                .procedure("flow")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "after_loop_statement",
            PointSelector::new("after_loop()")
                .procedure("flow")
                .anchor_occurrence(0),
        )
        .bind(
            "after_loop_invoke",
            PointSelector::new("after_loop()")
                .procedure("flow")
                .effect("invoke"),
        )
        .bind(
            "return_transfer",
            PointSelector::new("return final_value()")
                .procedure("flow")
                .effect("procedure_return"),
        )
        .bind(
            "normal_exit",
            PointSelector::new("def flow(keep, skip, repeat, stop)")
                .procedure("flow")
                .effect("normal_exit"),
        )
        .bind(
            "dead_invoke",
            PointSelector::new("dead_after_return()")
                .procedure("flow")
                .effect("invoke"),
        );

    graph.assert_successors(
        "while_decision",
        &[
            cfg_edge("loop_body", ControlEdgeKind::ConditionalTrue),
            cfg_edge("after_loop_statement", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "next_value_normal",
        &[cfg_edge("next_transfer", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "next_transfer",
        &[cfg_edge("while_condition_entry", ControlEdgeKind::LoopBack)],
    );
    graph.assert_successors(
        "redo_transfer",
        &[cfg_edge("loop_body", ControlEdgeKind::LoopBack)],
    );
    graph.assert_successors(
        "break_value_normal",
        &[cfg_edge("break_transfer", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "break_transfer",
        &[cfg_edge("after_loop_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "body_normal",
        &[cfg_edge("while_condition_entry", ControlEdgeKind::LoopBack)],
    );
    graph.assert_predecessors(
        "after_loop_statement",
        &[
            cfg_edge("while_decision", ControlEdgeKind::ConditionalFalse),
            cfg_edge("break_transfer", ControlEdgeKind::Normal),
        ],
    );
    graph.assert_successors(
        "return_transfer",
        &[cfg_edge("normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("entry", "after_loop_invoke");
    graph.assert_unreachable("return_transfer", "dead_invoke");
    graph.assert_unreachable("entry", "dead_invoke");
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn ruby_rescue_else_ensure_routes_normal_handled_and_unmatched_completion() {
    let project = InlineTestProject::with_language(Language::Ruby)
        .file(
            "ruby/rescue_flow.rb",
            r#"
                def guarded
                  begin
                    work()
                  rescue Problem
                    handled()
                  else
                    clean_path()
                  ensure
                    cleanup()
                  end
                  after_try()
                end
            "#,
        )
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "ruby/rescue_flow.rb");
    graph
        .bind(
            "entry",
            PointSelector::new("def guarded")
                .procedure("guarded")
                .effect("entry"),
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
            "handler_dispatch",
            PointSelector::new("begin")
                .procedure("guarded")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::SwitchCase),
        )
        .bind(
            "handler_entry",
            PointSelector::new("rescue Problem\n                    handled()")
                .procedure("guarded")
                .anchor_occurrence(0),
        )
        .bind(
            "unmatched_exception",
            PointSelector::new("begin")
                .procedure("guarded")
                .outgoing_kind(ControlEdgeKind::Cleanup),
        )
        .bind(
            "handled_normal",
            PointSelector::new("handled()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "handled_exceptional",
            PointSelector::new("handled()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Cleanup),
        )
        .bind(
            "clean_normal",
            PointSelector::new("clean_path()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "clean_exceptional",
            PointSelector::new("clean_path()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Cleanup),
        )
        .bind(
            "normal_cleanup_normal",
            PointSelector::new("cleanup()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal)
                .anchor_occurrence(6),
        )
        .bind(
            "exceptional_cleanup_normal",
            PointSelector::new("cleanup()")
                .procedure("guarded")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional)
                .anchor_occurrence(2),
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
            "exceptional_exit",
            PointSelector::new("def guarded")
                .procedure("guarded")
                .effect("exceptional_exit"),
        );

    graph.assert_successors(
        "work_exceptional",
        &[cfg_edge("handler_dispatch", ControlEdgeKind::Exceptional)],
    );
    graph.assert_successors(
        "handler_dispatch",
        &[
            cfg_edge("handler_entry", ControlEdgeKind::SwitchCase),
            cfg_edge("unmatched_exception", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_point_gap(
        "handler_dispatch",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );
    graph.assert_reachable("work_normal", "clean_normal");
    graph.assert_reachable("handled_normal", "normal_cleanup_normal");
    graph.assert_reachable("clean_normal", "normal_cleanup_normal");
    graph.assert_reachable("unmatched_exception", "exceptional_cleanup_normal");
    graph.assert_reachable("handled_exceptional", "exceptional_cleanup_normal");
    graph.assert_reachable("clean_exceptional", "exceptional_cleanup_normal");
    graph.assert_unreachable("clean_exceptional", "handler_entry");
    graph.assert_unreachable("handled_exceptional", "handler_entry");
    graph.assert_successors(
        "normal_cleanup_normal",
        &[cfg_edge("after_try_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "exceptional_cleanup_normal",
        &[cfg_edge("exceptional_exit", ControlEdgeKind::Exceptional)],
    );
    graph.assert_reachable("entry", "after_try_invoke");
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn ruby_return_and_shadowable_raise_run_ensure_before_completion() {
    const SOURCE: &str = r#"
        def returning
          begin
            return value()
          ensure
            cleanup_return()
          end
          dead_after_return()
        end

        def raising
          begin
            raise(problem())
          ensure
            cleanup_raise()
          end
          after_raise()
        end
    "#;
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("ruby/ensure_abrupt.rb", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "ruby/ensure_abrupt.rb");
    graph
        .bind(
            "return_entry",
            PointSelector::new("def returning")
                .procedure("returning")
                .effect("entry"),
        )
        .bind(
            "value_normal",
            PointSelector::new("value()")
                .procedure("returning")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "cleanup_return_normal",
            PointSelector::new("cleanup_return()")
                .procedure("returning")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal)
                .anchor_occurrence(6),
        )
        .bind(
            "return_transfer",
            PointSelector::new("return value()")
                .procedure("returning")
                .effect("procedure_return"),
        )
        .bind(
            "return_normal_exit",
            PointSelector::new("def returning")
                .procedure("returning")
                .effect("normal_exit"),
        )
        .bind(
            "dead_after_return",
            PointSelector::new("dead_after_return()")
                .procedure("returning")
                .effect("invoke"),
        )
        .bind(
            "problem_normal",
            PointSelector::new("problem()")
                .procedure("raising")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "raise_invoke",
            PointSelector::new("raise(problem())")
                .procedure("raising")
                .effect("invoke"),
        )
        .bind(
            "raise_normal",
            PointSelector::new("raise(problem())")
                .procedure("raising")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Cleanup)
                .anchor_occurrence(2),
        )
        .bind(
            "raise_exceptional",
            PointSelector::new("raise(problem())")
                .procedure("raising")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Cleanup)
                .anchor_occurrence(3),
        )
        .bind(
            "normal_cleanup_raise",
            PointSelector::new("cleanup_raise()")
                .procedure("raising")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal)
                .anchor_occurrence(6),
        )
        .bind(
            "exceptional_cleanup_raise",
            PointSelector::new("cleanup_raise()")
                .procedure("raising")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional)
                .anchor_occurrence(2),
        )
        .bind(
            "after_raise_statement",
            PointSelector::new("after_raise()")
                .procedure("raising")
                .anchor_occurrence(0),
        )
        .bind(
            "after_raise_invoke",
            PointSelector::new("after_raise()")
                .procedure("raising")
                .effect("invoke"),
        )
        .bind(
            "raise_exceptional_exit",
            PointSelector::new("def raising")
                .procedure("raising")
                .effect("exceptional_exit"),
        );

    graph.assert_reachable("return_entry", "value_normal");
    graph.assert_reachable("value_normal", "return_transfer");
    graph.assert_reachable("return_transfer", "cleanup_return_normal");
    graph.assert_successors(
        "cleanup_return_normal",
        &[cfg_edge("return_normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_unreachable("return_entry", "dead_after_return");

    graph.assert_successors(
        "problem_normal",
        &[cfg_edge("raise_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("raise_normal", "normal_cleanup_raise");
    graph.assert_reachable("normal_cleanup_raise", "after_raise_invoke");
    graph.assert_reachable("raise_exceptional", "exceptional_cleanup_raise");
    graph.assert_successors(
        "exceptional_cleanup_raise",
        &[cfg_edge(
            "raise_exceptional_exit",
            ControlEdgeKind::Exceptional,
        )],
    );
    graph.assert_unreachable("raise_exceptional", "after_raise_statement");
    let raising = procedure_named(&graph, "raising", ProcedureKind::Method);
    exact_call_site(raising, SOURCE, "raise(problem())");
    assert!(
        raising.points().iter().all(|point| point
            .events
            .iter()
            .all(|event| !matches!(&event.effect, SemanticEffect::Throw { .. }))),
        "shadowable Ruby raise syntax must not be terminalized as an unconditional throw"
    );
    graph.assert_adjacency_symmetric();
}

#[test]
fn ruby_block_and_lambda_abrupt_control_are_not_conflated() {
    const SOURCE: &str = r#"
        def block_control(items)
          items.each do |item|
            if item == :return
              return escape(item)
            end
            if item == :break
              break stop(item)
            end
            next skip(item) if item == :next
            redo if item == :redo
            block_body(item)
          end
          after_block()
        end

        def lambda_control
          callback = -> do
            return lambda_value()
            dead_inside_lambda()
          end
          after_lambda_creation()
        end
    "#;
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("ruby/non_local_control.rb", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "ruby/non_local_control.rb");
    graph
        .bind(
            "block_entry",
            PointSelector::new("do |item|")
                .effect("entry")
                .anchor_occurrence(0),
        )
        .bind(
            "block_return",
            PointSelector::new("return escape(item)").effect("gap"),
        )
        .bind(
            "block_body_entry",
            PointSelector::new("if item == :return").anchor_occurrence(0),
        )
        .bind(
            "block_nonlocal_boundary",
            PointSelector::new(
                r#"if item == :return
              return escape(item)
            end
            if item == :break
              break stop(item)
            end
            next skip(item) if item == :next
            redo if item == :redo
            block_body(item)"#,
            )
            .anchor_occurrence(0),
        )
        .bind(
            "block_break",
            PointSelector::new("break stop(item)").effect("gap"),
        )
        .bind(
            "block_next",
            PointSelector::new("next skip(item)").effect("procedure_return"),
        )
        .bind(
            "block_redo",
            PointSelector::new("redo")
                .occurrence(0)
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "block_normal_exit",
            PointSelector::new("do |item|").effect("normal_exit"),
        )
        .bind(
            "lambda_outer_entry",
            PointSelector::new("def lambda_control")
                .procedure("lambda_control")
                .effect("entry"),
        )
        .bind("lambda_entry", PointSelector::new("-> do").effect("entry"))
        .bind(
            "lambda_return",
            PointSelector::new("return lambda_value()").effect("procedure_return"),
        )
        .bind(
            "lambda_normal_exit",
            PointSelector::new("-> do").effect("normal_exit"),
        )
        .bind(
            "dead_lambda",
            PointSelector::new("dead_inside_lambda()").effect("invoke"),
        )
        .bind(
            "outer_after_lambda",
            PointSelector::new("after_lambda_creation()")
                .procedure("lambda_control")
                .effect("invoke"),
        );

    for boundary in ["block_return", "block_break"] {
        graph.assert_successors(
            boundary,
            &[cfg_edge("block_nonlocal_boundary", ControlEdgeKind::Normal)],
        );
        graph.assert_point_gap(
            boundary,
            SemanticCapability::NonLocalControl,
            SemanticGapKind::Unsupported,
        );
        graph.assert_reachable("block_entry", boundary);
        graph.assert_unreachable(boundary, "block_normal_exit");
    }
    graph.assert_successors("block_nonlocal_boundary", &[]);
    graph.assert_successors(
        "block_next",
        &[cfg_edge("block_normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "block_redo",
        &[cfg_edge("block_body_entry", ControlEdgeKind::LoopBack)],
    );
    graph.assert_successors(
        "lambda_return",
        &[cfg_edge("lambda_normal_exit", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("lambda_entry", "lambda_return");
    graph.assert_unreachable("lambda_entry", "dead_lambda");
    graph.assert_reachable("lambda_entry", "lambda_normal_exit");

    let block_control = procedure_named(&graph, "block_control", ProcedureKind::Method);
    for nested in [
        "escape(item)",
        "stop(item)",
        "skip(item)",
        "block_body(item)",
    ] {
        assert_no_exact_call_site(block_control, SOURCE, nested);
    }
    let lambda_control = procedure_named(&graph, "lambda_control", ProcedureKind::Method);
    for nested in ["lambda_value()", "dead_inside_lambda()"] {
        assert_no_exact_call_site(lambda_control, SOURCE, nested);
    }
    graph.assert_reachable("lambda_outer_entry", "outer_after_lambda");
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn ruby_nonlocal_block_control_runs_ensure_before_the_unknown_boundary() {
    const SOURCE: &str = r#"
        def return_from_block(items)
          items.each do |item|
            begin
              return escape(item)
            ensure
              return_cleanup(item)
            end
          end
          dead_after_return_block()
        end

        def break_from_block(items)
          items.each do |item|
            begin
              break stop(item)
            ensure
              break_cleanup(item)
            end
          end
          after_break_block()
        end
    "#;
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("ruby/nonlocal_cleanup.rb", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "ruby/nonlocal_cleanup.rb");
    graph
        .bind(
            "return_transfer",
            PointSelector::new("return escape(item)").effect("gap"),
        )
        .bind(
            "return_cleanup_normal",
            PointSelector::new("return_cleanup(item)")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal)
                .anchor_occurrence(6),
        )
        .bind(
            "return_unknown_boundary",
            PointSelector::new(
                r#"begin
              return escape(item)
            ensure
              return_cleanup(item)
            end"#,
            )
            .anchor_occurrence(0),
        )
        .bind(
            "break_transfer",
            PointSelector::new("break stop(item)").effect("gap"),
        )
        .bind(
            "break_cleanup_normal",
            PointSelector::new("break_cleanup(item)")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal)
                .anchor_occurrence(6),
        )
        .bind(
            "break_unknown_boundary",
            PointSelector::new(
                r#"begin
              break stop(item)
            ensure
              break_cleanup(item)
            end"#,
            )
            .anchor_occurrence(0),
        );

    for (transfer, cleanup, boundary) in [
        (
            "return_transfer",
            "return_cleanup_normal",
            "return_unknown_boundary",
        ),
        (
            "break_transfer",
            "break_cleanup_normal",
            "break_unknown_boundary",
        ),
    ] {
        graph.assert_point_gap(
            transfer,
            SemanticCapability::NonLocalControl,
            SemanticGapKind::Unsupported,
        );
        graph.assert_reachable(transfer, cleanup);
        graph.assert_successors(cleanup, &[cfg_edge(boundary, ControlEdgeKind::Normal)]);
        graph.assert_predecessors(boundary, &[cfg_edge(cleanup, ControlEdgeKind::Normal)]);
        graph.assert_successors(boundary, &[]);
    }
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn ruby_overrideable_negation_and_writer_assignments_keep_exact_control_boundaries() {
    const SOURCE: &str = r#"
        def operators(flag, receiver)
          !probe(flag)
          not predicate(flag)
          either ||= choose_rhs()
          both &&= confirm_rhs()
          receiver&.value = safe_rhs()
          receiver.value = writer_rhs()
          receiver[index_rhs()] = element_rhs()
          after_operators()
        end
    "#;
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("ruby/operators_and_writers.rb", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph =
        SemanticGraph::materialize(&project, &analyzer, "ruby/operators_and_writers.rb");
    graph
        .bind(
            "probe_normal",
            PointSelector::new("probe(flag)")
                .procedure("operators")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "bang_boundary",
            PointSelector::new("!probe(flag)")
                .procedure("operators")
                .effect("gap"),
        )
        .bind(
            "predicate_normal",
            PointSelector::new("predicate(flag)")
                .procedure("operators")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "not_boundary",
            PointSelector::new("not predicate(flag)")
                .procedure("operators")
                .effect("gap"),
        )
        .bind(
            "either_decision",
            PointSelector::new("either")
                .procedure("operators")
                .outgoing_kind(ControlEdgeKind::ConditionalFalse),
        )
        .bind(
            "choose_rhs_entry",
            PointSelector::new("choose_rhs()")
                .procedure("operators")
                .anchor_occurrence(0),
        )
        .bind(
            "either_terminal",
            PointSelector::new("either ||= choose_rhs()")
                .procedure("operators")
                .anchor_occurrence(1),
        )
        .bind(
            "either_merge",
            PointSelector::new("either ||= choose_rhs()")
                .procedure("operators")
                .anchor_occurrence(2),
        )
        .bind(
            "both_decision",
            PointSelector::new("both")
                .procedure("operators")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "confirm_rhs_entry",
            PointSelector::new("confirm_rhs()")
                .procedure("operators")
                .anchor_occurrence(0),
        )
        .bind(
            "both_terminal",
            PointSelector::new("both &&= confirm_rhs()")
                .procedure("operators")
                .anchor_occurrence(1),
        )
        .bind(
            "both_merge",
            PointSelector::new("both &&= confirm_rhs()")
                .procedure("operators")
                .anchor_occurrence(2),
        )
        .bind(
            "safe_decision",
            PointSelector::new("receiver&.value")
                .procedure("operators")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "safe_rhs_entry",
            PointSelector::new("safe_rhs()")
                .procedure("operators")
                .anchor_occurrence(0),
        )
        .bind(
            "safe_writer_dispatch",
            PointSelector::new("receiver&.value = safe_rhs()")
                .procedure("operators")
                .effect("gap")
                .anchor_occurrence(1),
        )
        .bind(
            "safe_merge",
            PointSelector::new("receiver&.value = safe_rhs()")
                .procedure("operators")
                .effect("gap")
                .anchor_occurrence(2),
        )
        .bind(
            "attribute_writer_dispatch",
            PointSelector::new("receiver.value = writer_rhs()")
                .procedure("operators")
                .effect("gap"),
        )
        .bind(
            "index_normal",
            PointSelector::new("index_rhs()")
                .procedure("operators")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "element_rhs_entry",
            PointSelector::new("element_rhs()")
                .procedure("operators")
                .anchor_occurrence(0),
        )
        .bind(
            "element_writer_dispatch",
            PointSelector::new("receiver[index_rhs()] = element_rhs()")
                .procedure("operators")
                .effect("gap"),
        );

    graph.assert_successors(
        "probe_normal",
        &[cfg_edge("bang_boundary", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "predicate_normal",
        &[cfg_edge("not_boundary", ControlEdgeKind::Normal)],
    );
    for boundary in ["bang_boundary", "not_boundary"] {
        for (capability, kind) in [
            (SemanticCapability::Calls, SemanticGapKind::Unsupported),
            (
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
            ),
            (
                SemanticCapability::NormalControlFlow,
                SemanticGapKind::Unknown,
            ),
        ] {
            graph.assert_point_gap(boundary, capability, kind);
        }
    }

    graph.assert_successors(
        "either_decision",
        &[
            cfg_edge("choose_rhs_entry", ControlEdgeKind::ConditionalFalse),
            cfg_edge("either_merge", ControlEdgeKind::ConditionalTrue),
        ],
    );
    graph.assert_predecessors(
        "either_merge",
        &[
            cfg_edge("either_terminal", ControlEdgeKind::Normal),
            cfg_edge("either_decision", ControlEdgeKind::ConditionalTrue),
        ],
    );
    graph.assert_successors(
        "both_decision",
        &[
            cfg_edge("confirm_rhs_entry", ControlEdgeKind::ConditionalTrue),
            cfg_edge("both_merge", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_predecessors(
        "both_merge",
        &[
            cfg_edge("both_terminal", ControlEdgeKind::Normal),
            cfg_edge("both_decision", ControlEdgeKind::ConditionalFalse),
        ],
    );

    graph.assert_successors(
        "safe_decision",
        &[
            cfg_edge("safe_rhs_entry", ControlEdgeKind::ConditionalTrue),
            cfg_edge("safe_merge", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_predecessors(
        "safe_merge",
        &[
            cfg_edge("safe_writer_dispatch", ControlEdgeKind::Normal),
            cfg_edge("safe_decision", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_unreachable("safe_merge", "safe_rhs_entry");
    graph.assert_successors(
        "index_normal",
        &[cfg_edge("element_rhs_entry", ControlEdgeKind::Normal)],
    );
    for writer in [
        "safe_writer_dispatch",
        "attribute_writer_dispatch",
        "element_writer_dispatch",
    ] {
        graph.assert_point_gap(
            writer,
            SemanticCapability::Calls,
            SemanticGapKind::Unsupported,
        );
        graph.assert_point_gap(
            writer,
            SemanticCapability::ExceptionalControlFlow,
            SemanticGapKind::Unknown,
        );
    }

    let operators = procedure_named(&graph, "operators", ProcedureKind::Method);
    for writer_target in ["receiver&.value", "receiver.value", "receiver[index_rhs()]"] {
        assert_no_exact_call_site(operators, SOURCE, writer_target);
    }
    for explicit_call in [
        "probe(flag)",
        "predicate(flag)",
        "choose_rhs()",
        "confirm_rhs()",
        "safe_rhs()",
        "writer_rhs()",
        "index_rhs()",
        "element_rhs()",
    ] {
        exact_call_site(operators, SOURCE, explicit_call);
    }
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn ruby_case_patterns_evaluate_explicit_calls_before_implicit_matching() {
    const SOURCE: &str = r#"
        def classify(subject)
          case subject_value(subject)
          when first_pattern(), second_pattern()
            first_match()
          when later_pattern()
            later_match()
          else
            no_match()
          end
        end

        def choose_without_subject
          case
          when predicate(), fallback()
            chosen()
          else
            not_chosen()
          end
        end
    "#;
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("ruby/case_pattern_calls.rb", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "ruby/case_pattern_calls.rb");
    graph
        .bind(
            "subject_normal",
            PointSelector::new("subject_value(subject)")
                .procedure("classify")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "first_pattern_entry",
            PointSelector::new("first_pattern()")
                .procedure("classify")
                .anchor_occurrence(0),
        )
        .bind(
            "first_pattern_normal",
            PointSelector::new("first_pattern()")
                .procedure("classify")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "first_pattern_exceptional",
            PointSelector::new("first_pattern()")
                .procedure("classify")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "first_pattern_decision",
            PointSelector::new("first_pattern()")
                .procedure("classify")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::SwitchCase)
                .anchor_occurrence(1),
        )
        .bind(
            "second_pattern_entry",
            PointSelector::new("second_pattern()")
                .procedure("classify")
                .anchor_occurrence(0),
        )
        .bind(
            "second_pattern_normal",
            PointSelector::new("second_pattern()")
                .procedure("classify")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "second_pattern_decision",
            PointSelector::new("second_pattern()")
                .procedure("classify")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::SwitchCase)
                .anchor_occurrence(1),
        )
        .bind(
            "later_pattern_entry",
            PointSelector::new("later_pattern()")
                .procedure("classify")
                .anchor_occurrence(0),
        )
        .bind(
            "later_pattern_normal",
            PointSelector::new("later_pattern()")
                .procedure("classify")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "later_pattern_decision",
            PointSelector::new("later_pattern()")
                .procedure("classify")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::SwitchCase)
                .anchor_occurrence(1),
        )
        .bind(
            "first_clause_body",
            PointSelector::new("when first_pattern(), second_pattern()\n            first_match()")
                .procedure("classify")
                .anchor_occurrence(0),
        )
        .bind(
            "later_clause_body",
            PointSelector::new("when later_pattern()\n            later_match()")
                .procedure("classify")
                .anchor_occurrence(0),
        )
        .bind(
            "else_body",
            PointSelector::new("else\n            no_match()")
                .procedure("classify")
                .anchor_occurrence(0),
        )
        .bind(
            "exceptional_exit",
            PointSelector::new("def classify(subject)")
                .procedure("classify")
                .effect("exceptional_exit"),
        )
        .bind(
            "predicate_normal",
            PointSelector::new("predicate()")
                .procedure("choose_without_subject")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "predicate_decision",
            PointSelector::new("predicate()")
                .procedure("choose_without_subject")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::SwitchCase)
                .anchor_occurrence(1),
        )
        .bind(
            "fallback_entry",
            PointSelector::new("fallback()")
                .procedure("choose_without_subject")
                .anchor_occurrence(0),
        )
        .bind(
            "fallback_normal",
            PointSelector::new("fallback()")
                .procedure("choose_without_subject")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "fallback_decision",
            PointSelector::new("fallback()")
                .procedure("choose_without_subject")
                .effect("gap")
                .outgoing_kind(ControlEdgeKind::SwitchCase)
                .anchor_occurrence(1),
        )
        .bind(
            "chosen_body",
            PointSelector::new("when predicate(), fallback()\n            chosen()")
                .procedure("choose_without_subject")
                .anchor_occurrence(0),
        )
        .bind(
            "not_chosen_body",
            PointSelector::new("else\n            not_chosen()")
                .procedure("choose_without_subject")
                .anchor_occurrence(0),
        );

    graph.assert_successors(
        "subject_normal",
        &[cfg_edge("first_pattern_entry", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "first_pattern_normal",
        &[cfg_edge("first_pattern_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "first_pattern_decision",
        &[
            cfg_edge("first_clause_body", ControlEdgeKind::SwitchCase),
            cfg_edge("second_pattern_entry", ControlEdgeKind::Normal),
        ],
    );
    graph.assert_predecessors(
        "second_pattern_entry",
        &[cfg_edge("first_pattern_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "second_pattern_normal",
        &[cfg_edge("second_pattern_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "second_pattern_decision",
        &[
            cfg_edge("first_clause_body", ControlEdgeKind::SwitchCase),
            cfg_edge("later_pattern_entry", ControlEdgeKind::Normal),
        ],
    );
    graph.assert_successors(
        "later_pattern_normal",
        &[cfg_edge("later_pattern_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "later_pattern_decision",
        &[
            cfg_edge("later_clause_body", ControlEdgeKind::SwitchCase),
            cfg_edge("else_body", ControlEdgeKind::Normal),
        ],
    );
    graph.assert_successors(
        "first_pattern_exceptional",
        &[cfg_edge("exceptional_exit", ControlEdgeKind::Exceptional)],
    );
    for decision in [
        "first_pattern_decision",
        "second_pattern_decision",
        "later_pattern_decision",
    ] {
        for (capability, kind) in [
            (SemanticCapability::Calls, SemanticGapKind::Unsupported),
            (
                SemanticCapability::ExceptionalControlFlow,
                SemanticGapKind::Unknown,
            ),
            (SemanticCapability::Values, SemanticGapKind::Unknown),
        ] {
            graph.assert_point_gap(decision, capability, kind);
        }
    }

    graph.assert_successors(
        "predicate_normal",
        &[cfg_edge("predicate_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "predicate_decision",
        &[
            cfg_edge("chosen_body", ControlEdgeKind::SwitchCase),
            cfg_edge("fallback_entry", ControlEdgeKind::Normal),
        ],
    );
    graph.assert_predecessors(
        "fallback_entry",
        &[cfg_edge("predicate_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "fallback_normal",
        &[cfg_edge("fallback_decision", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "fallback_decision",
        &[
            cfg_edge("chosen_body", ControlEdgeKind::SwitchCase),
            cfg_edge("not_chosen_body", ControlEdgeKind::Normal),
        ],
    );
    for decision in ["predicate_decision", "fallback_decision"] {
        graph.assert_point_gap(
            decision,
            SemanticCapability::Values,
            SemanticGapKind::Unknown,
        );
    }

    let classify = procedure_named(&graph, "classify", ProcedureKind::Method);
    for explicit_call in [
        "subject_value(subject)",
        "first_pattern()",
        "second_pattern()",
        "later_pattern()",
        "first_match()",
        "later_match()",
        "no_match()",
    ] {
        exact_call_site(classify, SOURCE, explicit_call);
    }
    let choose = procedure_named(&graph, "choose_without_subject", ProcedureKind::Method);
    for explicit_call in ["predicate()", "fallback()", "chosen()", "not_chosen()"] {
        exact_call_site(choose, SOURCE, explicit_call);
    }
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn ruby_callable_table_mutation_and_destructured_writers_do_not_fabricate_calls() {
    const SOURCE: &str = r#"
        class CallableTable
          alias replacement original
          undef retired

          def assign(receiver)
            receiver[index_call()], local = left_rhs(), right_rhs()
            after_assign(local)
          end
        end
    "#;
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("ruby/callable_table_and_destructuring.rb", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(
        &project,
        &analyzer,
        "ruby/callable_table_and_destructuring.rb",
    );
    graph
        .bind(
            "alias_mutation",
            PointSelector::new("alias replacement original").effect("gap"),
        )
        .bind(
            "undef_mutation",
            PointSelector::new("undef retired").effect("gap"),
        )
        .bind(
            "index_normal",
            PointSelector::new("index_call()")
                .procedure("assign")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "rhs_list_entry",
            PointSelector::new("left_rhs(), right_rhs()")
                .procedure("assign")
                .anchor_occurrence(0),
        )
        .bind(
            "left_rhs_normal",
            PointSelector::new("left_rhs()")
                .procedure("assign")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "right_rhs_entry",
            PointSelector::new("right_rhs()")
                .procedure("assign")
                .anchor_occurrence(0),
        )
        .bind(
            "writer_dispatch",
            PointSelector::new("receiver[index_call()], local = left_rhs(), right_rhs()")
                .procedure("assign")
                .effect("gap"),
        );

    graph.assert_successors(
        "alias_mutation",
        &[cfg_edge("undef_mutation", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "undef_mutation",
        &[cfg_edge("alias_mutation", ControlEdgeKind::Normal)],
    );
    for mutation in ["alias_mutation", "undef_mutation"] {
        graph.assert_point_gap(
            mutation,
            SemanticCapability::CallableReferences,
            SemanticGapKind::Unsupported,
        );
    }
    graph.assert_successors(
        "index_normal",
        &[cfg_edge("rhs_list_entry", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "left_rhs_normal",
        &[cfg_edge("right_rhs_entry", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "writer_dispatch",
        SemanticCapability::Calls,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "writer_dispatch",
        SemanticCapability::ExceptionalControlFlow,
        SemanticGapKind::Unknown,
    );

    for procedure in graph.artifact().procedures() {
        for method_name in ["replacement", "original", "retired"] {
            assert_no_exact_call_site(procedure, SOURCE, method_name);
        }
    }
    let assign = procedure_named(&graph, "assign", ProcedureKind::Method);
    assert_no_exact_call_site(assign, SOURCE, "receiver[index_call()]");
    for explicit_call in [
        "index_call()",
        "left_rhs()",
        "right_rhs()",
        "after_assign(local)",
    ] {
        exact_call_site(assign, SOURCE, explicit_call);
    }
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn ruby_nested_arguments_safe_navigation_and_attached_blocks_preserve_order() {
    const SOURCE: &str = r#"
        def evaluate(service)
          result = combine(first(), second(inner()))
          service&.run(argument()) do
            deferred_body()
          end
          after(result)
        end
    "#;
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("ruby/call_order.rb", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "ruby/call_order.rb");
    graph
        .bind(
            "entry",
            PointSelector::new("def evaluate(service)")
                .procedure("evaluate")
                .effect("entry"),
        )
        .bind(
            "first_normal",
            PointSelector::new("first()")
                .procedure("evaluate")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "second_expression",
            PointSelector::new("second(inner())")
                .procedure("evaluate")
                .anchor_occurrence(0),
        )
        .bind(
            "inner_normal",
            PointSelector::new("inner()")
                .procedure("evaluate")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
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
            "safe_decision",
            PointSelector::new("service&.run(argument()) do")
                .procedure("evaluate")
                .outgoing_kind(ControlEdgeKind::ConditionalTrue),
        )
        .bind(
            "argument_expression",
            PointSelector::new("argument()")
                .procedure("evaluate")
                .anchor_occurrence(0),
        )
        .bind(
            "argument_normal",
            PointSelector::new("argument()")
                .procedure("evaluate")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "safe_invoke",
            PointSelector::new(
                "service&.run(argument()) do\n            deferred_body()\n          end",
            )
            .procedure("evaluate")
            .effect("invoke"),
        )
        .bind(
            "safe_normal",
            PointSelector::new(
                "service&.run(argument()) do\n            deferred_body()\n          end",
            )
            .procedure("evaluate")
            .effect("call_continuation")
            .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "safe_exceptional",
            PointSelector::new(
                "service&.run(argument()) do\n            deferred_body()\n          end",
            )
            .procedure("evaluate")
            .effect("call_continuation")
            .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "after_statement",
            PointSelector::new("after(result)")
                .procedure("evaluate")
                .anchor_occurrence(0),
        )
        .bind(
            "after_invoke",
            PointSelector::new("after(result)")
                .procedure("evaluate")
                .effect("invoke"),
        )
        .bind(
            "closure_entry",
            PointSelector::new("do\n            deferred_body()\n          end").effect("entry"),
        )
        .bind(
            "deferred_body",
            PointSelector::new("deferred_body()").effect("invoke"),
        );

    graph.assert_successors(
        "first_normal",
        &[cfg_edge("second_expression", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("second_expression", "inner_normal");
    graph.assert_successors(
        "inner_normal",
        &[cfg_edge("second_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "second_normal",
        &[cfg_edge("combine_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("combine_normal", "safe_decision");
    graph.assert_successors(
        "safe_decision",
        &[
            cfg_edge("argument_expression", ControlEdgeKind::ConditionalTrue),
            cfg_edge("after_statement", ControlEdgeKind::ConditionalFalse),
        ],
    );
    graph.assert_successors(
        "argument_normal",
        &[cfg_edge("safe_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "safe_invoke",
        &[
            cfg_edge("safe_normal", ControlEdgeKind::Normal),
            cfg_edge("safe_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "safe_normal",
        &[cfg_edge("after_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_predecessors(
        "after_statement",
        &[
            cfg_edge("safe_decision", ControlEdgeKind::ConditionalFalse),
            cfg_edge("safe_normal", ControlEdgeKind::Normal),
        ],
    );
    graph.assert_reachable("closure_entry", "deferred_body");
    graph.assert_reachable("entry", "after_invoke");
    let evaluate = procedure_named(&graph, "evaluate", ProcedureKind::Method);
    assert_no_exact_call_site(evaluate, SOURCE, "deferred_body()");
    assert_call_site_gap(
        evaluate,
        SOURCE,
        "service&.run(argument()) do\n            deferred_body()\n          end",
        SemanticCapability::DeferredExecution,
        SemanticGapKind::Unknown,
    );
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn ruby_yield_retry_and_metaprogramming_boundaries_are_explicit() {
    const SOURCE: &str = r#"
        def invoke_block(value)
          yielded = yield(argument(value))
          after_yield(yielded)
        end

        def retrying
          begin
            attempt()
          rescue Temporary
            retry
          ensure
            retry_cleanup()
          end
          after_retry()
        end

        def dynamic(receiver)
          receiver.send(:target, nested())
          self.class.define_method(:generated) do
            generated_body()
          end
          after_dynamic()
        end
    "#;
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("ruby/boundaries.rb", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "ruby/boundaries.rb");
    graph
        .bind(
            "argument_normal",
            PointSelector::new("argument(value)")
                .procedure("invoke_block")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "yield_boundary",
            PointSelector::new("yield(argument(value))")
                .procedure("invoke_block")
                .effect("gap"),
        )
        .bind(
            "yield_assignment",
            PointSelector::new("yielded = yield(argument(value))")
                .procedure("invoke_block")
                .effect("assignment"),
        )
        .bind(
            "after_yield_statement",
            PointSelector::new("after_yield(yielded)")
                .procedure("invoke_block")
                .anchor_occurrence(0),
        )
        .bind(
            "after_yield",
            PointSelector::new("after_yield(yielded)")
                .procedure("invoke_block")
                .effect("invoke"),
        )
        .bind(
            "yield_exceptional_exit",
            PointSelector::new("def invoke_block(value)")
                .procedure("invoke_block")
                .effect("exceptional_exit"),
        )
        .bind(
            "protected_body_entry",
            PointSelector::new(
                "begin\n            attempt()\n          rescue Temporary\n            retry\n          ensure\n            retry_cleanup()\n          end",
            )
                .procedure("retrying")
                .anchor_occurrence(0),
        )
        .bind(
            "retry_transfer",
            PointSelector::new("retry")
                .procedure("retrying")
                .outgoing_kind(ControlEdgeKind::LoopBack),
        )
        .bind(
            "after_retry",
            PointSelector::new("after_retry()")
                .procedure("retrying")
                .effect("invoke"),
        )
        .bind(
            "nested_normal",
            PointSelector::new("nested()")
                .procedure("dynamic")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "send_invoke",
            PointSelector::new("receiver.send(:target, nested())")
                .procedure("dynamic")
                .effect("invoke"),
        )
        .bind(
            "define_method_invoke",
            PointSelector::new(
                "self.class.define_method(:generated) do\n            generated_body()\n          end",
            )
            .procedure("dynamic")
            .effect("invoke"),
        )
        .bind(
            "generated_closure_entry",
            PointSelector::new("do\n            generated_body()\n          end").effect("entry"),
        )
        .bind(
            "generated_body",
            PointSelector::new("generated_body()").effect("invoke"),
        )
        .bind(
            "after_dynamic",
            PointSelector::new("after_dynamic()")
                .procedure("dynamic")
                .effect("invoke"),
        );

    graph.assert_successors(
        "argument_normal",
        &[cfg_edge("yield_boundary", ControlEdgeKind::Normal)],
    );
    for (capability, kind) in [
        (SemanticCapability::Calls, SemanticGapKind::Unsupported),
        (
            SemanticCapability::NonLocalControl,
            SemanticGapKind::Unknown,
        ),
        (SemanticCapability::Values, SemanticGapKind::Unknown),
    ] {
        graph.assert_point_gap("yield_boundary", capability, kind);
    }
    graph.assert_successors(
        "yield_boundary",
        &[
            cfg_edge("yield_assignment", ControlEdgeKind::Normal),
            cfg_edge("yield_exceptional_exit", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_successors(
        "yield_assignment",
        &[cfg_edge("after_yield_statement", ControlEdgeKind::Normal)],
    );
    graph.assert_reachable("after_yield_statement", "after_yield");
    let invoke_block = procedure_named(&graph, "invoke_block", ProcedureKind::Method);
    assert_no_exact_call_site(invoke_block, SOURCE, "yield(argument(value))");

    graph.assert_successors(
        "retry_transfer",
        &[cfg_edge("protected_body_entry", ControlEdgeKind::LoopBack)],
    );
    graph.assert_reachable("protected_body_entry", "after_retry");

    graph.assert_successors(
        "nested_normal",
        &[cfg_edge("send_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_point_gap(
        "send_invoke",
        SemanticCapability::CallableReferences,
        SemanticGapKind::Unsupported,
    );
    graph.assert_point_gap(
        "define_method_invoke",
        SemanticCapability::CallableReferences,
        SemanticGapKind::Unknown,
    );
    let dynamic = procedure_named(&graph, "dynamic", ProcedureKind::Method);
    assert_call_site_gap(
        dynamic,
        SOURCE,
        "receiver.send(:target, nested())",
        SemanticCapability::Calls,
        SemanticGapKind::Unsupported,
    );
    assert_call_site_gap(
        dynamic,
        SOURCE,
        "self.class.define_method(:generated) do\n            generated_body()\n          end",
        SemanticCapability::Calls,
        SemanticGapKind::Unknown,
    );
    assert_call_site_gap(
        dynamic,
        SOURCE,
        "self.class.define_method(:generated) do\n            generated_body()\n          end",
        SemanticCapability::DeferredExecution,
        SemanticGapKind::Unknown,
    );
    assert_no_exact_call_site(dynamic, SOURCE, "generated_body()");
    graph.assert_reachable("generated_closure_entry", "generated_body");
    graph.assert_reachable("define_method_invoke", "after_dynamic");
    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}

#[test]
fn ruby_fibers_threads_and_ractors_keep_runtime_boundaries_explicit() {
    const SOURCE: &str = r#"
        def schedule
          fiber = Fiber.new do
            fiber_body()
          end
          thread = Thread.new do
            thread_body()
          end
          ractor = Ractor.new do
            ractor_body()
          end
          after_schedule(fiber, thread, ractor)
        end

        def suspend
          result = Fiber.yield(value())
          after_suspend(result)
        end
    "#;
    let project = InlineTestProject::with_language(Language::Ruby)
        .file("ruby/runtime_boundaries.rb", SOURCE)
        .build();
    let analyzer = project.workspace_analyzer(AnalyzerConfig::default());
    let mut graph = SemanticGraph::materialize(&project, &analyzer, "ruby/runtime_boundaries.rb");
    graph
        .bind(
            "fiber_invoke",
            PointSelector::new("Fiber.new do\n            fiber_body()\n          end")
                .procedure("schedule")
                .effect("invoke"),
        )
        .bind(
            "fiber_normal",
            PointSelector::new("Fiber.new do\n            fiber_body()\n          end")
                .procedure("schedule")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "fiber_exceptional",
            PointSelector::new("Fiber.new do\n            fiber_body()\n          end")
                .procedure("schedule")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "thread_invoke",
            PointSelector::new("Thread.new do\n            thread_body()\n          end")
                .procedure("schedule")
                .effect("invoke"),
        )
        .bind(
            "thread_normal",
            PointSelector::new("Thread.new do\n            thread_body()\n          end")
                .procedure("schedule")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "thread_exceptional",
            PointSelector::new("Thread.new do\n            thread_body()\n          end")
                .procedure("schedule")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "ractor_invoke",
            PointSelector::new("Ractor.new do\n            ractor_body()\n          end")
                .procedure("schedule")
                .effect("invoke"),
        )
        .bind(
            "ractor_normal",
            PointSelector::new("Ractor.new do\n            ractor_body()\n          end")
                .procedure("schedule")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "ractor_exceptional",
            PointSelector::new("Ractor.new do\n            ractor_body()\n          end")
                .procedure("schedule")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "after_schedule",
            PointSelector::new("after_schedule(fiber, thread, ractor)")
                .procedure("schedule")
                .effect("invoke"),
        )
        .bind(
            "fiber_closure_entry",
            PointSelector::new("do\n            fiber_body()\n          end").effect("entry"),
        )
        .bind(
            "fiber_body",
            PointSelector::new("fiber_body()").effect("invoke"),
        )
        .bind(
            "thread_closure_entry",
            PointSelector::new("do\n            thread_body()\n          end").effect("entry"),
        )
        .bind(
            "thread_body",
            PointSelector::new("thread_body()").effect("invoke"),
        )
        .bind(
            "ractor_closure_entry",
            PointSelector::new("do\n            ractor_body()\n          end").effect("entry"),
        )
        .bind(
            "ractor_body",
            PointSelector::new("ractor_body()").effect("invoke"),
        )
        .bind(
            "value_normal",
            PointSelector::new("value()")
                .procedure("suspend")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "yield_invoke",
            PointSelector::new("Fiber.yield(value())")
                .procedure("suspend")
                .effect("invoke"),
        )
        .bind(
            "yield_normal",
            PointSelector::new("Fiber.yield(value())")
                .procedure("suspend")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Normal),
        )
        .bind(
            "yield_exceptional",
            PointSelector::new("Fiber.yield(value())")
                .procedure("suspend")
                .effect("call_continuation")
                .outgoing_kind(ControlEdgeKind::Exceptional),
        )
        .bind(
            "after_suspend",
            PointSelector::new("after_suspend(result)")
                .procedure("suspend")
                .effect("invoke"),
        );

    graph.assert_successors(
        "fiber_invoke",
        &[
            cfg_edge("fiber_normal", ControlEdgeKind::Normal),
            cfg_edge("fiber_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_reachable("fiber_normal", "thread_invoke");
    graph.assert_successors(
        "thread_invoke",
        &[
            cfg_edge("thread_normal", ControlEdgeKind::Normal),
            cfg_edge("thread_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_reachable("thread_normal", "ractor_invoke");
    graph.assert_successors(
        "ractor_invoke",
        &[
            cfg_edge("ractor_normal", ControlEdgeKind::Normal),
            cfg_edge("ractor_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_reachable("ractor_normal", "after_schedule");
    graph.assert_reachable("fiber_closure_entry", "fiber_body");
    graph.assert_reachable("thread_closure_entry", "thread_body");
    graph.assert_reachable("ractor_closure_entry", "ractor_body");

    let schedule = procedure_named(&graph, "schedule", ProcedureKind::Method);
    for body in ["fiber_body()", "thread_body()", "ractor_body()"] {
        assert_no_exact_call_site(schedule, SOURCE, body);
    }
    for call_source in [
        "Fiber.new do\n            fiber_body()\n          end",
        "Thread.new do\n            thread_body()\n          end",
        "Ractor.new do\n            ractor_body()\n          end",
    ] {
        assert_call_site_gap(
            schedule,
            SOURCE,
            call_source,
            SemanticCapability::DeferredExecution,
            SemanticGapKind::Unknown,
        );
    }
    assert_call_site_gap(
        schedule,
        SOURCE,
        "Fiber.new do\n            fiber_body()\n          end",
        SemanticCapability::GeneratorSuspension,
        SemanticGapKind::Unknown,
    );
    for call_source in [
        "Thread.new do\n            thread_body()\n          end",
        "Ractor.new do\n            ractor_body()\n          end",
    ] {
        assert_call_site_gap(
            schedule,
            SOURCE,
            call_source,
            SemanticCapability::ConcurrentSpawn,
            SemanticGapKind::Unknown,
        );
    }

    graph.assert_successors(
        "value_normal",
        &[cfg_edge("yield_invoke", ControlEdgeKind::Normal)],
    );
    graph.assert_successors(
        "yield_invoke",
        &[
            cfg_edge("yield_normal", ControlEdgeKind::Normal),
            cfg_edge("yield_exceptional", ControlEdgeKind::Exceptional),
        ],
    );
    graph.assert_reachable("yield_normal", "after_suspend");
    let suspend = procedure_named(&graph, "suspend", ProcedureKind::Method);
    assert_call_site_gap(
        suspend,
        SOURCE,
        "Fiber.yield(value())",
        SemanticCapability::GeneratorSuspension,
        SemanticGapKind::Unknown,
    );

    graph.assert_adjacency_symmetric();
    let rendered = graph.render_topology();
    assert_eq!(rendered, graph.render_topology());
    assert!(!rendered.contains("ProgramPointId"));
    assert!(!rendered.contains("ControlEdgeId"));
}
